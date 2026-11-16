// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/confirm"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// brGuardHost answers the guard's scripts: whether systemd-run is there,
// arming, reverting at once, and confirming, whose exit status is
// confirmRC. ran counts each.
type brGuardHost struct {
	mu                           sync.Mutex
	noSystemd, armFails, revFail bool
	confirmRC                    int
	reload                       string // "!" fails the reload
	onConfirm                    func()
	ran                          map[string]int
}

func (g *brGuardHost) answer(script string) (string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ran == nil {
		g.ran = map[string]int{}
	}
	switch {
	case strings.Contains(script, "command -v systemd-run"):
		g.ran["check"]++
		if g.noSystemd {
			return "", 1
		}
	case strings.Contains(script, "systemd-run --quiet"):
		g.ran["arm"]++
		if g.armFails {
			return "mkdir: read-only file system", 1
		}
	case strings.Contains(script, "is-active --quiet"):
		g.ran["confirm"]++
		if g.onConfirm != nil {
			g.onConfirm()
		}
		return "", g.confirmRC
	case strings.Contains(script, "revert.sh; fi"):
		g.ran["revert"]++
		if g.revFail {
			return "revert.sh: no such file", 1
		}
	case strings.Contains(script, "systemctl reload"):
		g.ran["reload"]++
		if g.reload == "!" {
			return "", 1
		}
	}
	return "", 0
}

func (g *brGuardHost) count(what string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.ran[what]
}

// brGuard dials a host answered by g, for guarded.
func brGuard(t *testing.T, g *brGuardHost) (*hostConn, cty.Value) {
	t.Helper()
	conn := fullSSH(cty.ObjectVal(unitHost(t, g.answer)))
	h, err := dialConnection(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	return h, conn
}

func TestGuardedConfirmsOverANewLogin(t *testing.T) {
	g := &brGuardHost{}
	h, conn := brGuard(t, g)
	changed := false
	guard := confirm.Guard{ID: newGuardID(), After: time.Minute, Reload: "systemctl reload sshd"}
	if err := guarded(ctx, h, conn, guard, func() error { changed = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !changed || g.count("arm") != 1 || g.count("reload") != 1 || g.count("confirm") != 1 || g.count("revert") != 0 {
		t.Errorf("changed %v, ran %v", changed, g.ran)
	}
}

// Whatever goes wrong before the confirm puts the old state back at once,
// and says whether that worked; a host without systemd isn't changed.
func TestGuardedRevertsAFailedChange(t *testing.T) {
	boom := errors.New("write failed")
	for name, c := range map[string]struct {
		host   *brGuardHost
		change error
		reload string
		want   string
	}{
		"no systemd":    {host: &brGuardHost{noSystemd: true}, want: "has no systemd-run"},
		"arm fails":     {host: &brGuardHost{armFails: true}, want: "scheduling the revert: exit status 1"},
		"change fails":  {change: boom, want: "write failed; the old state was put back"},
		"revert fails":  {host: &brGuardHost{revFail: true}, change: boom, want: "reverting it failed too"},
		"reload fails":  {host: &brGuardHost{reload: "!"}, reload: "systemctl reload sshd", want: "reload failed (exit status 1"},
		"late login":    {host: &brGuardHost{confirmRC: 3}, want: "logged in again, but too late"},
		"reload is bad": {host: &brGuardHost{reload: "!", revFail: true}, reload: "systemctl reload sshd", want: "reload failed (exit status 1: ); and reverting it failed too"},
	} {
		t.Run(name, func(t *testing.T) {
			g := c.host
			if g == nil {
				g = &brGuardHost{}
			}
			h, conn := brGuard(t, g)
			ran := false
			err := guarded(ctx, h, conn, confirm.Guard{ID: newGuardID(), After: time.Minute, Reload: c.reload}, func() error { ran = true; return c.change })
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if armed := g.count("arm") == 1 && !g.armFails; ran != armed {
				t.Errorf("changed %v with the revert armed %v", ran, armed)
			}
			if wantRevert := c.change != nil || c.reload != ""; (g.count("revert") == 1) != wantRevert {
				t.Errorf("reverted %d times, want it %v", g.count("revert"), wantRevert)
			}
		})
	}
}

// Stopping while the confirm fails leaves the revert to the host, and says
// so, without waiting out the deadline.
func TestGuardedStoppedBeforeConfirming(t *testing.T) {
	stop, cancel := context.WithCancel(ctx)
	defer cancel()
	g := &brGuardHost{confirmRC: 1, onConfirm: cancel}
	h, conn := brGuard(t, g)
	start := time.Now()
	err := guarded(stop, h, conn, confirm.Guard{ID: newGuardID(), After: time.Minute}, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "the host will put the old state back on its own within 1m0s") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("took %s", time.Since(start))
	}
}

// A new login takes become's password from its file, and fails when the
// file or the host can't be read.
func TestFreshLogin(t *testing.T) {
	attrs := unitHost(t, (&unitScripts{}).answer)
	r, done, err := freshLogin(ctx, fullSSH(cty.ObjectVal(attrs)))
	if err != nil {
		t.Fatal(err)
	}
	done()
	if _, ok := r.(*ssh.Become); ok {
		t.Error("became root without become")
	}

	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("hunter2\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	attrs["become"], attrs["become_password_file"] = cty.True, cty.StringVal(pw)
	r, done, err = freshLogin(ctx, fullSSH(cty.ObjectVal(attrs)))
	if err != nil {
		t.Fatal(err)
	}
	done()
	if b, ok := r.(*ssh.Become); !ok || string(b.Password) != "hunter2" {
		t.Errorf("runner %#v", r)
	}

	attrs["become_password_file"] = cty.StringVal(filepath.Join(t.TempDir(), "missing"))
	if _, _, err := freshLogin(ctx, fullSSH(cty.ObjectVal(attrs))); err == nil || !strings.Contains(err.Error(), "reading become_password_file") {
		t.Errorf("a missing password file: %v", err)
	}
	attrs["private_key_file"] = cty.StringVal(filepath.Join(t.TempDir(), "missing"))
	if _, _, err := freshLogin(ctx, fullSSH(cty.ObjectVal(attrs))); err == nil {
		t.Error("logged in with a missing key")
	}
	attrs["port"] = cty.NumberIntVal(1)
	attrs["private_key_file"] = cty.NullVal(cty.String)
	if _, _, err := freshLogin(ctx, fullSSH(cty.ObjectVal(attrs))); err == nil {
		t.Error("logged in on port 1")
	}
}
