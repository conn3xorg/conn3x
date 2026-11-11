// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package service

import "testing"

// Names and systemctl show's answers pair up in order: an alias keeps its
// own name, a unit nothing provides is left out, and masked, static and
// indirect never read as enabled.
func TestParseInventory(t *testing.T) {
	out := "cron.service\ngetty@tty1.service\nmissing.service\nnginx.service\nsshd.service\nsystemd-journald.service\nuuidd.service\n--\n" +
		"ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\nId=cron.service\n\n" +
		"ActiveState=active\nUnitFileState=enabled-runtime\nLoadState=loaded\nId=getty@tty1.service\n\n" +
		"ActiveState=inactive\nUnitFileState=\nLoadState=not-found\nId=missing.service\n\n" +
		"ActiveState=inactive\nUnitFileState=masked\nLoadState=masked\nId=nginx.service\n\n" +
		"ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\nId=ssh.service\n\n" +
		"ActiveState=active\nUnitFileState=static\nLoadState=loaded\nId=systemd-journald.service\n\n" +
		"ActiveState=inactive\nUnitFileState=indirect\nLoadState=loaded\nId=uuidd.service\n"
	got, err := parseInventory(out)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		state   string
		enabled bool
	}{
		"cron": {"active", true}, "getty@tty1": {"active", true}, "nginx": {"inactive", false},
		"sshd": {"active", true}, "systemd-journald": {"active", false}, "uuidd": {"inactive", false},
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
	if _, err := parseInventory("a.service\nb.service\n--\nId=a.service\n"); err == nil {
		t.Error("two names and one answer parsed")
	}
}
