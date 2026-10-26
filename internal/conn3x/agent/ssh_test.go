// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb"
	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

const agentPkg = "github.com/opentofu/opentofu/cmd/conn3x-agent"

// buildAgent builds the agent for this machine.
func buildAgent(tb testing.TB) string {
	tb.Helper()
	bin := filepath.Join(tb.TempDir(), "conn3x-agent")
	if out, err := exec.Command("go", "build", "-o", bin, agentPkg).CombinedOutput(); err != nil {
		tb.Fatalf("building the agent: %v\n%s", err, out)
	}
	return bin
}

func dialServer(tb testing.TB, s *sshtest.Server) *ssh.Client {
	tb.Helper()
	c, err := ssh.Dial(context.Background(), ssh.Config{Host: s.Host, Port: s.Port, User: "test", PrivateKey: s.ClientKey, KnownHostsFile: s.KnownHosts(tb)})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { c.Close() })
	return c
}

// sshAgent starts the agent binary over SSH, as conn3x does on a host.
func sshAgent(tb testing.TB, c *ssh.Client, bin string) *Client {
	tb.Helper()
	p, err := c.Start(context.Background(), "exec "+ssh.Quote(bin))
	if err != nil {
		tb.Fatal(err)
	}
	a, err := NewClient(context.Background(), p)
	if err != nil {
		tb.Fatalf("%v (agent stderr: %s)", err, p.Stderr())
	}
	tb.Cleanup(func() { a.Close() })
	return a
}

func TestAgentOverSSHConformance(t *testing.T) {
	bin := buildAgent(t)
	s := sshtest.New(t)
	shell := dialServer(t, s)

	t.Run("Local", func(t *testing.T) {
		moduletest.RunnerConformance(t, func(*testing.T) modules.Runner { return moduletest.Local{} })
	})
	t.Run("shell", func(t *testing.T) {
		moduletest.RunnerConformance(t, func(*testing.T) modules.Runner { return shell })
	})
	before := len(s.Commands())
	var a *Client
	t.Run("agent", func(t *testing.T) {
		moduletest.RunnerConformance(t, func(t *testing.T) modules.Runner {
			a = sshAgent(t, dialServer(t, s), bin)
			return a
		})
		// Same directory and environment as a shell command gets.
		for _, cmd := range []string{"pwd", `printf %s "$LC_ALL"`} {
			got, err := a.Run(ctx, cmd, nil)
			if err != nil {
				t.Fatal(err)
			}
			want, err := shell.Run(ctx, cmd, nil)
			if err != nil {
				t.Fatal(err)
			}
			if string(got.Stdout) != string(want.Stdout) {
				t.Errorf("%s: agent says %q, the shell says %q", cmd, got.Stdout, want.Stdout)
			}
		}
	})
	// Everything the agent ran went through the one session that started it.
	if got := s.Commands()[before:]; len(got) != 3 || !strings.HasPrefix(got[0], "exec ") {
		t.Fatalf("the server ran %q; want the agent started once and two shell commands", got)
	}
	t.Run("file reads", func(t *testing.T) {
		moduletest.FileConformance(t, shell, shell)
		moduletest.FileConformance(t, shell, sshAgent(t, dialServer(t, s), bin))
	})
}

func TestAgentDependencies(t *testing.T) {
	allowed := []string{
		agentPkg,
		"github.com/opentofu/opentofu/internal/conn3x/agent/agentpb",
		"github.com/opentofu/opentofu/internal/conn3x/agent/server",
		// protowire and the two internal packages it uses, not the runtime.
		"google.golang.org/protobuf/encoding/protowire",
		"google.golang.org/protobuf/internal/detrand",
		"google.golang.org/protobuf/internal/errors",
		// systemd over D-Bus, for unit reads.
		"github.com/coreos/go-systemd/v22/dbus",
		"github.com/godbus/dbus/v5",
	}
	cmd := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", agentPkg)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if !slices.Contains(allowed, dep) {
			t.Errorf("the agent imports %s; it may use only the standard library, protowire, go-systemd's D-Bus client and its own packages", dep)
		}
	}

	for _, arch := range []string{"amd64", "arm64"} {
		bin := filepath.Join(t.TempDir(), "conn3x-agent")
		build := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", bin, agentPkg)
		build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building for linux/%s: %v\n%s", arch, err, out)
		}
		raw, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		var gz bytes.Buffer
		w, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
		_, _ = w.Write(raw)
		w.Close()
		t.Logf("linux/%s agent: %d bytes, %d gzipped", arch, len(raw), gz.Len())
		if gz.Len() > 2_000_000 {
			t.Errorf("linux/%s agent is %d bytes gzipped; the budget is 2,000,000", arch, gz.Len())
		}
	}
}

// BenchmarkRun times one small command per way of running it, against a
// local host and ones 25 ms and 50 ms away. The server delays each write,
// so a request and its reply cost about one delay. agent-root is the
// agent started through sudo, as become runs it.
func BenchmarkRun(b *testing.B) {
	bin := buildAgent(b)
	for _, mode := range []string{"shell", "shell-sudo", "agent", "agent-root"} {
		for _, rtt := range []struct {
			name  string
			delay time.Duration
		}{{"rtt0", 0}, {"rtt25ms", 25 * time.Millisecond}, {"rtt50ms", 50 * time.Millisecond}} {
			b.Run(mode+"/"+rtt.name, func(b *testing.B) {
				s := sshtest.New(b)
				s.Latency = rtt.delay
				c := dialServer(b, s)
				var r modules.Runner = c
				switch mode {
				case "shell-sudo":
					s.FakeSudo(b, "nopasswd")
					r = &ssh.Become{Client: c}
				case "agent":
					r = sshAgent(b, c, bin)
				case "agent-root":
					s.FakeSudo(b, "nopasswd")
					a, err := startBecome(context.Background(), c, "exec "+ssh.Quote(bin), &ssh.Become{Client: c})
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() { a.Close() })
					r = a
				}
				ctx := context.Background()
				if _, err := r.Run(ctx, "true", nil); err != nil {
					b.Fatal(err)
				}
				for b.Loop() {
					if _, err := r.Run(ctx, "true", nil); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestAgentBinaryStopsCleanlyWhenOutputBreaks(t *testing.T) {
	cmd := exec.Command(buildAgent(t))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	if _, err := agentpb.ReadFrame(stdout); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "pid")
	if err := agentpb.WriteFrame(stdin, &agentpb.Envelope{ID: 1, Exec: &agentpb.ExecRequest{Cmd: "sleep 60 & echo $! > " + pidFile + "; wait"}}); err != nil {
		t.Fatal(err)
	}
	pid := waitForPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	// With nobody reading, the next reply hits a broken pipe. That must
	// not kill the agent outright and leave the sleep behind.
	stdout.Close()
	if err := agentpb.WriteFrame(stdin, &agentpb.Envelope{ID: 2, Exec: &agentpb.ExecRequest{Cmd: "true"}}); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if ws := cmd.ProcessState.Sys().(syscall.WaitStatus); ws.Signaled() {
		t.Fatalf("the agent died of %v", ws.Signal())
	}
	waitGone(t, pid)
}
