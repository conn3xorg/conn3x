// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/agent"
	"github.com/opentofu/opentofu/internal/providers"
)

// localAgent is the agent built for this machine, gzipped, with its sum.
var localAgent = sync.OnceValues(func() (func(string) ([]byte, [32]byte, error), error) {
	dir, err := os.MkdirTemp("", "conn3x-agent-test")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "conn3x-agent")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/opentofu/opentofu/cmd/conn3x-agent").CombinedOutput(); err != nil {
		return nil, errors.New(err.Error() + "\n" + string(out))
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		return nil, err
	}
	var gz bytes.Buffer
	w, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	sum := sha256.Sum256(raw)
	return func(string) ([]byte, [32]byte, error) { return gz.Bytes(), sum, nil }, nil
})

// newAgentTest is a fileTest whose host has a home of its own and whose
// provider offers the agent built for this machine.
func newAgentTest(t *testing.T) (*fileTest, string) {
	t.Helper()
	payload, err := localAgent()
	if err != nil {
		t.Fatal(err)
	}
	old := agentPayload
	agentPayload = payload
	t.Cleanup(func() { agentPayload = old })
	t.Setenv("CONN3X_AGENT", "")
	f := newFileTest(t)
	home := t.TempDir()
	f.server.Env = append(f.server.Env, "HOME="+home, "XDG_CACHE_HOME="+filepath.Join(home, ".cache"))
	return f, home
}

// withConn sets attributes of the test's ssh block.
func (f *fileTest) withConn(attrs map[string]cty.Value) {
	vals := f.conn.AsValueMap()
	for k, v := range attrs {
		vals[k] = v
	}
	f.conn = cty.ObjectVal(vals)
}

// commands are what the host ran, with the test's directory made generic.
func (f *fileTest) commands() []string {
	var out []string
	for _, c := range f.server.Commands() {
		out = append(out, strings.ReplaceAll(c, f.server.Dir, "DIR"))
	}
	return out
}

func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out = append(out, strings.TrimPrefix(path, dir)+" "+info.Mode().String()+" "+info.ModTime().String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func isProbe(cmd string) bool { return strings.Contains(cmd, "uname -m") }

// lifecycle creates a file, reads it back and changes it.
func (f *fileTest) lifecycle() {
	f.t.Helper()
	state := f.create("one\n", nil)
	state = f.read(state)
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("two\n")})
	f.apply(state, f.plan(state, cfg).PlannedState, cfg)
}

func TestAgentFalseRunsNoProbe(t *testing.T) {
	var want []string
	for _, tc := range []struct {
		name string
		attr cty.Value
	}{
		{"unset", cty.NilVal},
		{"agent = false", cty.False},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newAgentTest(t)
			agentPayload = func(string) ([]byte, [32]byte, error) {
				t.Error("the agent was asked for")
				return nil, [32]byte{}, agent.ErrUnavailable
			}
			if tc.attr != cty.NilVal {
				f.withConn(map[string]cty.Value{"agent": tc.attr})
			}
			f.lifecycle()
			got := f.commands()
			for _, c := range got {
				if isProbe(c) || strings.HasPrefix(c, "exec ") {
					t.Errorf("with the agent off the host ran %q", c)
				}
			}
			if want == nil {
				want = got
			} else if !slices.Equal(got, want) {
				t.Errorf("commands differ from the default:\ngot  %q\nwant %q", got, want)
			}
		})
	}
}

func TestEnvOffMeansShell(t *testing.T) {
	for _, tc := range []struct {
		name      string
		env       string
		attr      cty.Value
		wantAgent bool
	}{
		{"CONN3X_AGENT=off", "off", cty.NilVal, false},
		{"CONN3X_AGENT=on", "on", cty.NilVal, true},
		{"attribute false beats CONN3X_AGENT=on", "on", cty.False, false},
		{"attribute true beats CONN3X_AGENT=off", "off", cty.True, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newAgentTest(t)
			t.Setenv("CONN3X_AGENT", tc.env)
			if tc.attr != cty.NilVal {
				f.withConn(map[string]cty.Value{"agent": tc.attr})
			}
			f.lifecycle()
			cmds := f.commands()
			if got := slices.ContainsFunc(cmds, isProbe); got != tc.wantAgent {
				t.Fatalf("probed = %v, want %v; commands:\n%s", got, tc.wantAgent, strings.Join(cmds, "\n---\n"))
			}
		})
	}
}

func TestReadNeverUploads(t *testing.T) {
	f, home := newAgentTest(t)
	// State as an earlier apply left it, read with the agent on.
	state := f.create("hi\n", nil)
	f.withConn(map[string]cty.Value{"agent": cty.True})
	vals := state.AsValueMap()
	vals["ssh"] = f.conn
	state = cty.ObjectVal(vals)

	before, start := listTree(t, home), len(f.server.Commands())
	got := f.read(state)
	if !got.GetAttr("content").RawEquals(cty.StringVal("hi\n")) {
		t.Fatalf("read content = %#v", got.GetAttr("content"))
	}
	if after := listTree(t, home); !slices.Equal(before, after) {
		t.Fatalf("a read wrote to the host:\nbefore %q\nafter  %q", before, after)
	}
	cmds := f.commands()[start:]
	if len(cmds) == 0 || !isProbe(cmds[0]) {
		t.Fatalf("a read with the agent on should probe first; ran:\n%s", strings.Join(cmds, "\n---\n"))
	}
	for _, c := range cmds[1:] {
		if isProbe(c) || strings.Contains(c, "mktemp") {
			t.Errorf("the read ran %q", c)
		}
	}
}

func TestApplyUploadsAndUsesAgent(t *testing.T) {
	f, home := newAgentTest(t)
	f.withConn(map[string]cty.Value{"agent": cty.True})
	state := f.create("hello\n", nil)
	if got, _ := os.ReadFile(f.path); string(got) != "hello\n" {
		t.Fatalf("file holds %q", got)
	}
	// Probe, upload and start; the file module's own commands went
	// through the agent.
	cmds := f.commands()
	if len(cmds) != 3 || !isProbe(cmds[0]) || !strings.HasPrefix(cmds[2], "exec ") {
		t.Fatalf("apply ran:\n%s", strings.Join(cmds, "\n---\n"))
	}
	if entries, _ := os.ReadDir(filepath.Join(home, ".cache", "conn3x")); len(entries) == 0 {
		t.Fatal("nothing cached on the host")
	}
	// Reads in the same run use the running agent.
	f.read(state)
	if got := f.commands(); len(got) != 3 {
		t.Fatalf("the read ran %q outside the agent", got[3:])
	}
}

func TestAgentDeathSurfacesError(t *testing.T) {
	f, _ := newAgentTest(t)
	f.withConn(map[string]cty.Value{"agent": cty.True})
	c := commandTest{f}
	// The agent is the command's parent; anything else is left alone.
	kill := `case $(ps -o comm= -p $PPID) in *agent-*) kill -9 $PPID ;; *) exit 1 ;; esac`
	_, resp := c.cycle(cty.NullVal(c.obj(nil).Type()), c.obj(map[string]cty.Value{"command": cty.StringVal(kill)}))
	if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), agent.ErrAgentGone.Error()) {
		t.Fatalf("apply after the agent died = %v, want ErrAgentGone", resp.Diagnostics.Err())
	}
	for _, cmd := range f.server.Commands() {
		if strings.Contains(cmd, kill) {
			t.Fatalf("the command was retried through the shell: %q", cmd)
		}
	}

	// The next resource gets a new agent, from the cache.
	before := len(f.server.Commands())
	_, resp = c.cycle(cty.NullVal(c.obj(nil).Type()), c.obj(map[string]cty.Value{"command": cty.StringVal("true")}))
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	if cmds := f.commands()[before:]; len(cmds) != 2 || !isProbe(cmds[0]) || !strings.HasPrefix(cmds[1], "exec ") {
		t.Fatalf("after the agent died the next apply ran:\n%s", strings.Join(cmds, "\n---\n"))
	}
}

func isRootStart(cmd string) bool { return strings.HasPrefix(cmd, "exec sudo -S -p 'conn3x-sudo-") }

func TestBecomeUsesTheAgent(t *testing.T) {
	f, _ := newAgentTest(t)
	f.server.FakeSudo(t, "nopasswd")
	f.withConn(map[string]cty.Value{"agent": cty.True, "become": cty.True})
	f.lifecycle()
	cmds := f.commands()
	if n := len(slices.DeleteFunc(slices.Clone(cmds), func(c string) bool { return !isRootStart(c) })); n != 1 {
		t.Fatalf("started %d root agents, want 1; commands:\n%s", n, strings.Join(cmds, "\n---\n"))
	}
	// Besides sudo's checks, every command went through the agent.
	for _, c := range cmds {
		if !isProbe(c) && !isRootStart(c) && !strings.Contains(c, "mktemp") && !strings.Contains(c, "sudo -n -- true") {
			t.Errorf("ran outside the agent: %q", c)
		}
	}
}

func TestBecomeOneRootAgentPerHost(t *testing.T) {
	f, _ := newAgentTest(t)
	f.server.FakeSudo(t, "password:s3cret")
	pw := func(p string) cty.Value {
		file := filepath.Join(t.TempDir(), "pw")
		if err := os.WriteFile(file, []byte(p+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return cty.StringVal(file)
	}
	f.withConn(map[string]cty.Value{"agent": cty.True, "become": cty.True, "become_password_file": pw("s3cret")})
	first := f.conn
	f.withConn(map[string]cty.Value{"user": cty.StringVal("other")})
	second := f.conn

	// Two logins to the same host, dialled at once.
	conns := make([]*hostConn, 2)
	var wg sync.WaitGroup
	for i, conn := range []cty.Value{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := dialForApply(ctx, conn)
			if err != nil {
				t.Error(err)
			}
			conns[i] = h
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	if conns[0] == conns[1] {
		t.Fatal("two logins shared one connection")
	}
	if conns[0].agent == nil || conns[0].agent != conns[1].agent {
		t.Fatal("the two logins don't share one root agent")
	}
	for _, h := range conns {
		if res, err := h.Run(ctx, `echo "$SUDO_USER"`, nil); err != nil || string(res.Stdout) != "fake\n" {
			t.Fatalf("got %q, %v", res.Stdout, err)
		}
	}
	if n := len(slices.DeleteFunc(f.server.Commands(), func(c string) bool { return !isRootStart(c) })); n != 1 {
		t.Fatalf("started %d root agents, want 1", n)
	}

	// A login whose sudo fails doesn't get the running root agent.
	f.withConn(map[string]cty.Value{"user": cty.StringVal("third"), "become_password_file": pw("wrong")})
	if _, err := dialForApply(ctx, f.conn); err == nil || !strings.Contains(err.Error(), "incorrect password") {
		t.Fatalf("dial with a wrong password = %v, want the incorrect password error", err)
	}
}

func TestUpgradeStateWithoutAgentAttribute(t *testing.T) {
	f := newFileTest(t)
	if err := os.WriteFile(f.path, []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// State from before the agent attribute existed.
	old := `{"id":"h:` + f.path + `","path":"` + f.path + `","content":"hi\n","mode":"0644","owner":null,"group":null,"on_remove":"forget","sha256":"` + sum("hi\n") + `",
	"ssh":{"host":"` + f.server.Host + `","port":` + strconv.Itoa(f.server.Port) + `,"user":"test","private_key_file":"` + f.server.KeyFile(t) + `","host_key":null,
	"known_hosts_file":"` + f.server.KnownHosts(t) + `","become":null,"become_password_file":null,"timeout":null}}`
	resp := f.p.UpgradeResourceState(ctx, providers.UpgradeResourceStateRequest{TypeName: "conn3x_file", RawStateJSON: []byte(old)})
	if resp.Diagnostics.HasErrors() {
		t.Fatal(resp.Diagnostics.Err())
	}
	ssh := resp.UpgradedState.GetAttr("ssh")
	if !ssh.Type().HasAttribute("agent") || !ssh.GetAttr("agent").IsNull() {
		t.Fatalf("upgraded ssh block = %#v, want agent present and null", ssh)
	}
	if got := f.read(resp.UpgradedState); !got.GetAttr("content").RawEquals(cty.StringVal("hi\n")) {
		t.Fatalf("read after upgrade = %#v", got.GetAttr("content"))
	}
	if slices.ContainsFunc(f.commands(), isProbe) {
		t.Fatal("upgraded state without the attribute started the agent")
	}
}

func TestRequireTurnsUnavailableIntoError(t *testing.T) {
	for _, tc := range []struct {
		name string
		attr cty.Value
	}{{"env alone", cty.NilVal}, {"with agent = true", cty.True}} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newAgentTest(t)
			t.Setenv("CONN3X_AGENT", "require")
			if tc.attr != cty.NilVal {
				f.withConn(map[string]cty.Value{"agent": tc.attr})
			}
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "uname"), []byte("#!/bin/sh\necho riscv64\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			f.server.Env = append(f.server.Env, "PATH="+bin+":"+os.Getenv("PATH"))

			cfg := f.config(map[string]cty.Value{"content": cty.StringVal("hi\n")})
			null := cty.NullVal(cfg.Type())
			resp := f.p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{
				TypeName: "conn3x_file", PriorState: null, PlannedState: f.plan(null, cfg).PlannedState, Config: cfg,
			})
			if !resp.Diagnostics.HasErrors() || !strings.Contains(resp.Diagnostics.Err().Error(), "riscv64") {
				t.Fatalf("apply on a host that can't run the agent = %v, want an error naming riscv64", resp.Diagnostics.Err())
			}
			if _, err := os.Stat(f.path); err == nil {
				t.Fatal("the file was written through the shell anyway")
			}
		})
	}
}

func TestRequireLetsReadsWaitForAnApply(t *testing.T) {
	f, _ := newAgentTest(t)
	state := f.create("hi\n", nil) // agent off
	t.Setenv("CONN3X_AGENT", "require")
	// Nothing is cached yet, so the read uses the shell; the apply then
	// uploads and uses the agent.
	f.read(state)
	cfg := f.config(map[string]cty.Value{"content": cty.StringVal("two\n")})
	before := len(f.server.Commands())
	f.apply(state, f.plan(state, cfg).PlannedState, cfg)
	if cmds := f.commands()[before:]; len(cmds) != 3 || !strings.HasPrefix(cmds[2], "exec ") {
		t.Fatalf("apply under require ran:\n%s", strings.Join(cmds, "\n---\n"))
	}
}
