// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/agent"
	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/moduletest"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// TestAgentConformance checks, on each image, that the agent's native
// reads give what the shell gives: files through file.Read, systemd units
// through service.Read and the properties systemctl show prints, and the
// same again as root through sudo.
func TestAgentConformance(t *testing.T) {
	for _, image := range linuxImages {
		t.Run(image, func(t *testing.T) {
			ctx := context.Background()
			h := startHost(t, image)
			sh := h.dial(t, "root")
			a, err := agent.Attach(ctx, sh, agent.Options{Upload: true, Version: "e2e", Payload: builtAgent})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { a.Close() })

			t.Run("files", func(t *testing.T) { moduletest.FileConformance(t, sh, a) })
			t.Run("units", func(t *testing.T) { unitConformance(t, sh, a) })

			t.Run("become", func(t *testing.T) {
				addDeploy(h, "", "")
				become := &ssh.Become{Client: h.dial(t, "deploy")}
				root, err := agent.Attach(ctx, become.Client, agent.Options{Upload: true, Version: "e2e", Payload: builtAgent, Become: become})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { root.Close() })

				// Only root can read it, and both must.
				if _, err := root.ReadFile(ctx, "/etc/shadow"); err != nil {
					t.Fatalf("the root agent can't read /etc/shadow itself: %v", err)
				}
				got, err := file.Read(ctx, root, "/etc/shadow")
				if err != nil {
					t.Fatal(err)
				}
				want, err := file.Read(ctx, become, "/etc/shadow")
				if err != nil {
					t.Fatal(err)
				}
				if got != want || !strings.Contains(got.Content, "deploy:") {
					t.Fatalf("/etc/shadow: the agent sees %s %s:%s, %d bytes; sudo sees %s %s:%s, %d bytes",
						got.Mode, got.Owner, got.Group, len(got.Content), want.Mode, want.Owner, want.Group, len(want.Content))
				}
				moduletest.FileConformance(t, become, root)
				unitConformance(t, become, root)
			})
		})
	}
}

// unitConformance sets up units in every state service.Read tells apart,
// then checks the agent answers each one natively, as systemctl does.
func unitConformance(t *testing.T, sh modules.Runner, a *agent.Client) {
	t.Helper()
	ctx := context.Background()
	setup := `set -e
unit() { printf '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=%s\n[Install]\nWantedBy=multi-user.target\n' "$2" > /etc/systemd/system/$1.service; }
unit conn3x-on /bin/true
unit conn3x-off /bin/true
unit conn3x-failed /bin/false
unit conn3x-stale /bin/true
systemctl daemon-reload
systemctl enable --now conn3x-on.service
systemctl start conn3x-stale.service
systemctl start conn3x-failed.service || true
systemctl mask conn3x-masked.service
echo '# changed' >> /etc/systemd/system/conn3x-stale.service`
	if res, err := sh.Run(ctx, setup, nil); err != nil || res.ExitCode != 0 {
		t.Fatalf("setting up units: %v %s", err, res.Stderr)
	}
	t.Cleanup(func() {
		_, _ = sh.Run(ctx, "systemctl disable --now conn3x-on.service; systemctl stop conn3x-stale.service; systemctl unmask conn3x-masked.service; rm -f /etc/systemd/system/conn3x-*.service; systemctl reset-failed; systemctl daemon-reload", nil)
	})

	for _, c := range []struct {
		name string
		want service.Actual
	}{
		{"conn3x-on", service.Actual{Exists: true, Running: true, Enabled: true}},
		{"conn3x-off", service.Actual{Exists: true}},
		{"conn3x-failed", service.Actual{Exists: true}},
		{"conn3x-masked", service.Actual{Exists: true}},
		{"conn3x-stale", service.Actual{Exists: true, Running: true, NeedsReload: true}},
		{"conn3x-nope", service.Actual{}},
		{"sshd", service.Actual{Exists: true, Running: true, Enabled: true}}, // an alias on Debian and Ubuntu
	} {
		t.Run(c.name, func(t *testing.T) {
			props, err := a.ReadUnit(ctx, service.Unit(c.name))
			if err != nil {
				t.Fatalf("the agent can't read the unit itself: %v", err)
			}
			res, err := sh.Run(ctx, "systemctl show -p LoadState,ActiveState,UnitFileState,NeedDaemonReload -- "+service.Unit(c.name), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(res.Stdout)), "\n") {
				k, v, _ := strings.Cut(line, "=")
				if props[k] != v {
					t.Errorf("%s: the agent says %q, systemctl says %q", k, props[k], v)
				}
			}
			got, err := service.Read(ctx, a, c.name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := service.Read(ctx, sh, c.name)
			if err != nil {
				t.Fatal(err)
			}
			if got != want || want != c.want {
				t.Fatalf("the agent reads %+v, the shell %+v, want %+v", got, want, c.want)
			}
		})
	}
}

// dial connects to h as user with the test key.
func (h *host) dial(t *testing.T, user string) *ssh.Client {
	t.Helper()
	key, err := os.ReadFile(h.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(h.port)
	c, err := ssh.Dial(context.Background(), ssh.Config{Host: "127.0.0.1", Port: port, User: user, PrivateKey: key, KnownHostsFile: h.knownHosts})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// builtAgent is the agent TestMain's build put in the payload directory.
func builtAgent(arch string) ([]byte, [32]byte, error) {
	_, here, _, _ := runtime.Caller(0)
	gz, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "internal", "conn3x", "agent", "payload", "conn3x-agent-linux-"+arch+".gz"))
	if err != nil {
		return nil, [32]byte{}, err
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, [32]byte{}, err
	}
	raw, err := io.ReadAll(r)
	return gz, sha256.Sum256(raw), err
}
