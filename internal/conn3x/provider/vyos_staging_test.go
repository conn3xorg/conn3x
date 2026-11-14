// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh/sshtest"
	"github.com/opentofu/opentofu/internal/providers"
)

// fakeVyOS answers the way VyOS 2026.11.13-0016-rolling did, closely enough
// for staging: set lines in a candidate, commit-confirm that needs its y,
// confirm and save, and the commit-confirm timer.
type fakeVyOS struct {
	mu       sync.Mutex
	running  []string
	pending  bool
	commits  int
	confirms int
	saves    int
}

func (f *fakeVyOS) run(cmd string, stdin []byte) (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch cmd {
	case "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands":
		var out []string
		for _, l := range f.running {
			f := strings.Fields(l)
			out = append(out, strings.Join(f[:len(f)-1], " ")+" '"+f[len(f)-1]+"'")
		}
		return strings.Join(out, "\n") + "\n", 0
	case "systemctl is-active commit-confirm.timer":
		if f.pending {
			return "active\n", 0
		}
		return "inactive\n", 3
	case "vbash -s":
	default:
		return "  Invalid command\n", 0
	}
	lines := strings.Split(strings.TrimSpace(string(stdin)), "\n")
	candidate := slices.Clone(f.running)
	var b strings.Builder
	for n := 0; n < len(lines); n++ {
		l := lines[n]
		switch {
		case strings.HasPrefix(l, "set "):
			candidate = append(candidate, l)
		case strings.HasPrefix(l, "delete "):
			p := "set " + strings.TrimPrefix(l, "delete ")
			candidate = slices.DeleteFunc(candidate, func(c string) bool { return c == p || strings.HasPrefix(c, p+" ") })
		case strings.HasPrefix(l, "commit-confirm"):
			if n+1 >= len(lines) || lines[n+1] != "y" {
				return "Please respond with yes/y or no/n\n", 0
			}
			n++
			f.running, f.pending = candidate, true
			f.commits++
			b.WriteString("Initialized commit-confirm; 5 minutes to confirm before reload\n")
		case l == "confirm" && f.pending:
			f.pending = false
			f.confirms++
			b.WriteString("Reload timer stopped\n")
		case l == "save":
			f.saves++
		}
	}
	return b.String(), 0
}

// Three steps on a router in a circuit stage their lines, and its commit
// sends them in one commit-confirm, with one confirm and one save.
func TestVyOSStepsShareOneCommit(t *testing.T) {
	s := sshtest.New(t)
	f := &fakeVyOS{running: []string{"set system host-name r1", "set system config-management commit-confirm action reload"}}
	s.SetExec(f.run)
	ssh := eosStep("conn3x_vyos_commit", nil, map[string]cty.Value{
		"host": cty.StringVal(s.Host), "port": cty.NumberIntVal(int64(s.Port)), "user": cty.StringVal("vyos"),
		"private_key_file": cty.StringVal(s.KeyFile(t)), "known_hosts_file": cty.StringVal(s.KnownHosts(t)),
		"confirm_after": cty.StringVal("10ms"),
	}).GetAttr("ssh")
	t.Cleanup(func() { _ = FinishEOS() })
	step := func(kind cliKind, typ string, attrs map[string]cty.Value) {
		t.Helper()
		attrs["circuit"] = cty.StringVal("edge")
		v := onSwitch(eosStep(typ, attrs, nil), ssh)
		if err := create(func(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
			return kind.apply(ctx, req)
		}, v); err != nil {
			t.Fatal(err)
		}
	}
	step(vyosHostnameKind, "conn3x_vyos_hostname", map[string]cty.Value{"name": cty.StringVal("r2")})
	step(vyosInterfaceKind, "conn3x_vyos_interface", map[string]cty.Value{"name": cty.StringVal("eth1"), "mtu": cty.NumberIntVal(9000)})
	step(vyosConfigKind, "conn3x_vyos_config", map[string]cty.Value{"lines": cty.ListVal([]cty.Value{cty.StringVal("set service ntp server 10.0.0.1")})})
	if f.commits != 0 {
		t.Fatalf("%d commits before the circuit's commit", f.commits)
	}
	backups := t.TempDir()
	commit := onSwitch(eosStep("conn3x_vyos_commit", map[string]cty.Value{"id": cty.StringVal("c"), "circuit": cty.StringVal("edge"), "removals": cty.StringVal("r"), "backup_dir": cty.StringVal(backups)}, nil), ssh)
	applyCommit := func(req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
		return applyCLICommit(vyosPlatform)(ctx, req)
	}
	if err := create(applyCommit, commit); err != nil {
		t.Fatal(err)
	}
	// device_backup_dir: the configuration from before the change, once.
	files, _ := os.ReadDir(backups)
	if len(files) != 1 {
		t.Fatalf("%d backups, want 1", len(files))
	}
	if b, _ := os.ReadFile(filepath.Join(backups, files[0].Name())); !strings.Contains(string(b), "host-name r1") || strings.Contains(string(b), "host-name r2") {
		t.Errorf("the backup isn't the configuration from before the change:\n%s", b)
	}
	// A commit with nothing staged changes nothing, and backs nothing up.
	if err := create(applyCommit, commit); err != nil {
		t.Fatal(err)
	}
	if files, _ := os.ReadDir(backups); len(files) != 1 {
		t.Errorf("%d backups after a commit with nothing to do, want 1", len(files))
	}
	if f.commits != 1 || f.confirms != 1 || f.saves != 1 {
		t.Errorf("%d commits, %d confirms, %d saves; want 1 each", f.commits, f.confirms, f.saves)
	}
	for _, want := range []string{"set system host-name r2", "set interfaces ethernet eth1 mtu 9000", "set service ntp server 10.0.0.1"} {
		if !slices.Contains(f.running, want) {
			t.Errorf("running is missing %q: %q", want, f.running)
		}
	}
	if slices.Contains(f.running, "set system host-name r1") {
		t.Error("the old host name is still there")
	}
}
