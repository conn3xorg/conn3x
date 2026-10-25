// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package agent

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
)

const testVersion = "1.2.3"

var testAgent = sync.OnceValues(func() ([]byte, error) {
	dir, err := os.MkdirTemp("", "conn3x-agent-test")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "conn3x-agent")
	if out, err := exec.Command("go", "build", "-o", bin, agentPkg).CombinedOutput(); err != nil {
		return nil, errors.New(err.Error() + "\n" + string(out))
	}
	return os.ReadFile(bin)
})

// testGz is the test agent gzipped, made once.
var testGz = sync.OnceValue(func() []byte {
	raw, _ := testAgent()
	var b bytes.Buffer
	w, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	return b.Bytes()
})

// agentPayload is a Payload that offers the agent built for this machine,
// whatever the host's architecture.
func agentPayload(t testing.TB) func(string) ([]byte, [32]byte, error) {
	t.Helper()
	raw, err := testAgent()
	if err != nil {
		t.Fatal(err)
	}
	gz, sum := testGz(), sha256.Sum256(raw)
	return func(string) ([]byte, [32]byte, error) { return gz, sum, nil }
}

// testHost is an sshtest server with a home directory of its own.
type testHost struct {
	*sshtest.Server
	home string
}

func newTestHost(t *testing.T) *testHost {
	t.Helper()
	s := sshtest.New(t)
	home := t.TempDir()
	s.Env = append(s.Env, "HOME="+home, "XDG_CACHE_HOME="+filepath.Join(home, ".cache"))
	return &testHost{Server: s, home: home}
}

// fakeCommand puts a script called name first on the host's PATH.
func (h *testHost) fakeCommand(t *testing.T, name, script string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.Env = append(h.Env, "PATH="+bin+":"+os.Getenv("PATH"))
}

func (h *testHost) cacheDir() string { return filepath.Join(h.home, ".cache", "conn3x") }

// attach dials the host afresh and attaches an agent to it.
func (h *testHost) attach(t *testing.T, o Options) (*Client, error) {
	t.Helper()
	c := dialServer(t, h.Server)
	a, err := Attach(ctx, c, o)
	if a != nil {
		t.Cleanup(func() { a.Close() })
	}
	return a, err
}

// tree lists every path under dir with its mode, size and modification time.
func tree(t *testing.T, dir string) []string {
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

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != ".lock" { // only where flock(1) exists
			out = append(out, e.Name())
		}
	}
	return out
}

func agentName(t testing.TB) string {
	raw, err := testAgent()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return "agent-" + testVersion + "-" + hex.EncodeToString(sum[:])[:12]
}

func mustRun(t *testing.T, a *Client, cmd string) string {
	t.Helper()
	res, err := a.Run(ctx, cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(res.Stdout)
}

func TestAttachUploadsThenReusesCache(t *testing.T) {
	h := newTestHost(t)
	o := Options{Upload: true, Version: testVersion, Payload: agentPayload(t)}
	a, err := h.attach(t, o)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRun(t, a, "echo hi"); got != "hi\n" {
		t.Fatalf("agent said %q", got)
	}
	if got := h.Commands(); len(got) != 3 {
		t.Fatalf("first attach ran %d commands, want probe, upload and start:\n%s", len(got), strings.Join(got, "\n---\n"))
	}
	// Only the verified agent is left: no temp file, no canary.
	if got := names(t, h.cacheDir()); !slices.Equal(got, []string{agentName(t)}) {
		t.Fatalf("cache holds %q, want just %s", got, agentName(t))
	}
	for path, want := range map[string]os.FileMode{h.cacheDir(): os.ModeDir | 0o700, filepath.Join(h.cacheDir(), agentName(t)): 0o700} {
		if info, err := os.Lstat(path); err != nil || info.Mode() != want {
			t.Errorf("%s: %v %v, want mode %v", path, info.Mode(), err, want)
		}
	}

	// A second run finds the cached agent and uploads nothing.
	before := len(h.Commands())
	a2, err := h.attach(t, o)
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, a2, "true")
	if got := h.Commands()[before:]; len(got) != 2 {
		t.Fatalf("second attach ran %d commands, want probe and start:\n%s", len(got), strings.Join(got, "\n---\n"))
	}
}

func TestAttachWithoutUploadNeverWrites(t *testing.T) {
	h := newTestHost(t)
	before := tree(t, h.home)
	_, err := h.attach(t, Options{Version: testVersion, Payload: agentPayload(t)})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attach without a cached agent = %v, want ErrUnavailable", err)
	}
	if after := tree(t, h.home); !slices.Equal(before, after) {
		t.Fatalf("attach without upload changed the home directory:\nbefore %q\nafter  %q", before, after)
	}
	if got := h.Commands(); len(got) != 1 {
		t.Fatalf("ran %d commands, want just the probe", len(got))
	}

	// Once an apply has uploaded it, a plan uses the cached agent.
	if _, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: agentPayload(t)}); err != nil {
		t.Fatal(err)
	}
	before = tree(t, h.home)
	a, err := h.attach(t, Options{Version: testVersion, Payload: agentPayload(t)})
	if err != nil {
		t.Fatalf("attach with a cached agent: %v", err)
	}
	mustRun(t, a, "true")
	if after := tree(t, h.home); !slices.Equal(before, after) {
		t.Fatalf("attaching a cached agent changed the home directory:\nbefore %q\nafter  %q", before, after)
	}
}

func TestAttachReplacesCorruptCache(t *testing.T) {
	h := newTestHost(t)
	o := Options{Upload: true, Version: testVersion, Payload: agentPayload(t)}
	if _, err := h.attach(t, o); err != nil {
		t.Fatal(err)
	}
	// The cached file is damaged; running it would leave a mark.
	cached := filepath.Join(h.cacheDir(), agentName(t))
	mark := filepath.Join(t.TempDir(), "ran")
	if err := os.WriteFile(cached, []byte("#!/bin/sh\ntouch "+mark+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := h.attach(t, Options{Version: testVersion, Payload: o.Payload}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attach without upload over a corrupt cache = %v, want ErrUnavailable", err)
	}
	a, err := h.attach(t, o)
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, a, "true")
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("the corrupt cached file was run")
	}
	raw, _ := testAgent()
	if got, _ := os.ReadFile(cached); sha256.Sum256(got) != sha256.Sum256(raw) {
		t.Fatal("the corrupt cached file was not replaced")
	}
}

func TestUploadInterruptedLeavesNoFinalFile(t *testing.T) {
	raw, err := testAgent()
	if err != nil {
		t.Fatal(err)
	}
	gz, sum := gzipped(t, raw), sha256.Sum256(raw)
	for name, payload := range map[string][]byte{
		// The connection dropped part way through.
		"truncated": gz[:len(gz)/2],
		// What arrived isn't what was sent.
		"wrong content": gzipped(t, append(slices.Clone(raw), 0)),
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t)
			_, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: func(string) ([]byte, [32]byte, error) {
				return payload, sum, nil
			}})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("attach = %v, want ErrUnavailable", err)
			}
			for _, dir := range []string{h.cacheDir(), filepath.Join(h.home, ".conn3x")} {
				if got := names(t, dir); len(got) != 0 {
					t.Errorf("%s holds %q after a failed upload, want nothing", dir, got)
				}
			}
		})
	}
}

func TestAttachSkipsUnusableDir(t *testing.T) {
	for name, spoil := range map[string]func(t *testing.T, dir string){
		"symlink": func(t *testing.T, dir string) {
			target := t.TempDir()
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if got := names(t, target); len(got) != 0 {
					t.Errorf("the symlink's target got %q", got)
				}
			})
		},
		"open to others": func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if got := names(t, dir); len(got) != 0 {
					t.Errorf("the open directory got %q", got)
				}
			})
		},
		"a file": func(t *testing.T, dir string) {
			if err := os.WriteFile(dir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t)
			if err := os.MkdirAll(filepath.Dir(h.cacheDir()), 0o700); err != nil {
				t.Fatal(err)
			}
			spoil(t, h.cacheDir())
			a, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: agentPayload(t)})
			if err != nil {
				t.Fatal(err)
			}
			mustRun(t, a, "true")
			if got := names(t, filepath.Join(h.home, ".conn3x")); !slices.Equal(got, []string{agentName(t)}) {
				t.Fatalf("$HOME/.conn3x holds %q, want the agent", got)
			}
		})
	}
}

func TestAttachUnknownArch(t *testing.T) {
	h := newTestHost(t)
	h.fakeCommand(t, "uname", "echo riscv64")
	before := tree(t, h.home)
	_, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: agentPayload(t)})
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "riscv64") {
		t.Fatalf("attach = %v, want ErrUnavailable naming riscv64", err)
	}
	if got := h.Commands(); len(got) != 1 {
		t.Fatalf("ran %d commands, want just the probe", len(got))
	}
	if after := tree(t, h.home); !slices.Equal(before, after) {
		t.Fatalf("an unknown architecture still wrote to the host:\n%q", after)
	}
}

func TestAttachFapolicydActive(t *testing.T) {
	h := newTestHost(t)
	h.fakeCommand(t, "systemctl", `[ "$*" = "is-active --quiet fapolicyd" ]`)
	before := tree(t, h.home)
	_, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: agentPayload(t)})
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "fapolicyd") {
		t.Fatalf("attach = %v, want ErrUnavailable naming fapolicyd", err)
	}
	if got := h.Commands(); len(got) != 1 {
		t.Fatalf("ran %d commands, want just the probe", len(got))
	}
	if after := tree(t, h.home); !slices.Equal(before, after) {
		t.Fatalf("fapolicyd was active but the host was written to:\n%q", after)
	}
}

func TestAttachWithoutPayloadRunsNothing(t *testing.T) {
	h := newTestHost(t)
	_, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: func(arch string) ([]byte, [32]byte, error) {
		return nil, [32]byte{}, ErrUnavailable
	}})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attach = %v, want ErrUnavailable", err)
	}
	if got := h.Commands(); len(got) != 0 {
		t.Fatalf("a build without an agent ran %q on the host", got)
	}
}

func TestPruneKeepsTwo(t *testing.T) {
	h := newTestHost(t)
	dir := h.cacheDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, name := range []string{"agent-0.1.0-aaaaaaaaaaaa", "agent-0.2.0-bbbbbbbbbbbb", "agent-0.3.0-cccccccccccc", ".agent.stale", ".agent.fresh"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0o700); err != nil {
			t.Fatal(err)
		}
		age := time.Duration(5-i) * time.Hour
		if name == ".agent.fresh" {
			age = time.Minute // another upload may still be writing it
		}
		if err := os.Chtimes(path, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	a, err := h.attach(t, Options{Upload: true, Version: testVersion, Payload: agentPayload(t)})
	if err != nil {
		t.Fatal(err)
	}
	mustRun(t, a, "true")
	got := names(t, dir)
	want := []string{".agent.fresh", "agent-0.3.0-cccccccccccc", agentName(t)}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("after pruning the cache holds %q, want %q", got, want)
	}
}

func TestConcurrentAttach(t *testing.T) {
	h := newTestHost(t)
	o := Options{Upload: true, Version: testVersion, Payload: agentPayload(t)}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			a, err := h.attach(t, o)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := a.Run(ctx, "true", nil); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := names(t, h.cacheDir()); !slices.Equal(got, []string{agentName(t)}) {
		t.Fatalf("after concurrent attaches the cache holds %q, want just the agent", got)
	}
}
