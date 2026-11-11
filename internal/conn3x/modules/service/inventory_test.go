// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package service

import "testing"

// Each name finds systemctl show's block by its Id or one of its Names,
// whatever order they come in: an alias keeps its own name, an escaped
// instance name is kept as systemd prints it, a unit nothing provides is
// left out, and masked, static and indirect never read as enabled.
func TestParseInventory(t *testing.T) {
	out := "cron.service\nmissing.service\nnginx.service\nssh.service\nsshd.service\nsystemd-fsck@dev-disk-by\\x2duuid-1234.service\nsystemd-journald.service\nuuidd.service\n--\n" +
		"ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\nId=ssh.service\nNames=ssh.service sshd.service\n\n" +
		"ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\nId=cron.service\nNames=cron.service\n\n" +
		"ActiveState=inactive\nUnitFileState=\nLoadState=not-found\nId=missing.service\nNames=missing.service\n\n" +
		"ActiveState=inactive\nUnitFileState=masked\nLoadState=masked\nId=nginx.service\nNames=nginx.service\n\n" +
		"ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\nId=ssh.service\nNames=ssh.service sshd.service\n\n" +
		"ActiveState=active\nUnitFileState=static\nLoadState=loaded\nId=systemd-journald.service\nNames=systemd-journald.service\n\n" +
		"ActiveState=inactive\nUnitFileState=indirect\nLoadState=loaded\nId=uuidd.service\nNames=uuidd.service\n\n" +
		"ActiveState=active\nUnitFileState=static\nLoadState=loaded\nId=systemd-fsck@dev-disk-by\\x2duuid-1234.service\nNames=systemd-fsck@dev-disk-by\\x2duuid-1234.service\n"
	got, err := parseInventory(out)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		state   string
		enabled bool
	}{
		"cron": {"active", true}, "nginx": {"inactive", false}, "ssh": {"active", true}, "sshd": {"active", true},
		`systemd-fsck@dev-disk-by\x2duuid-1234`: {"active", false}, "systemd-journald": {"active", false}, "uuidd": {"inactive", false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for name, w := range want {
		if u, ok := got[name]; !ok || u.State != w.state || u.Enabled() != w.enabled {
			t.Errorf("%s: %+v enabled %v, want %+v", name, u, u.Enabled(), w)
		}
	}
	if got["nginx"].UnitFileState != "masked" {
		t.Errorf("nginx: %+v", got["nginx"])
	}
	if _, err := parseInventory("a.service\nb.service\n--\nId=a.service\nNames=a.service\n"); err == nil {
		t.Error("a name systemctl show said nothing about was dropped without an error")
	}
	if got, err := parseInventory("\n--\n"); err != nil || len(got) != 0 {
		t.Errorf("no services: %v %v", got, err)
	}
}
