// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

// Each kind reads what the host has, sorted, and leaves out what a step
// can't adopt: system users, swap, commented lines.
func TestListHostReadsEachKind(t *testing.T) {
	timers := "\x1ebackup\x1f[Timer]\nOnCalendar=daily\nPersistent=true\n\x1f[Unit]\nDescription=Nightly backup\n[Service]\nType=oneshot\nUser=deploy\nExecStart=/usr/local/bin/backup.sh\n\x1f\n" +
		"\x1etorn\x1fonly two parts"
	host := (&unitScripts{}).
		on("cat /etc/os-release", "ID=ubuntu\nID_LIKE=debian\n").
		on("dpkg --print-architecture", "amd64\nnginx\tamd64\t1.24\ncurl\tamd64\t8.5\n").
		on("list-unit-files", "ssh.service\n--\nId=ssh.service\nNames=ssh.service sshd.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n").
		on("cat /etc/sysctl.conf", "# a comment\n; another\n\nnot a setting\nvm.swappiness = 10\n-net.ipv4.ip_forward=1\nvm.swappiness=  20   \n").
		on("*.timer", timers).
		on("getent passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nnobody:x:65534:65534::/:/usr/sbin/nologin\nshort:x:1001\nbob:x:1001:1001::/home/bob:/bin/sh\n").
		on("cat /etc/fstab", "# /etc/fstab\nUUID=1 / ext4 defaults 0 1\nUUID=2 none swap sw 0 0\n/dev/vdb1 /data xfs defaults 0 2\nproc\n")
	conn := cty.ObjectVal(unitHost(t, host.answer))
	for kind, want := range map[string][]string{
		"packages": {"curl", "nginx"},
		"services": {"ssh"},
		"sysctl":   {"net.ipv4.ip_forward", "vm.swappiness"},
		"timers":   {"backup"},
		"users":    {"alice", "bob"},
		"mounts":   {"/", "/data"},
	} {
		names, values, err := ListHost(ctx, kind, conn)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !reflect.DeepEqual(names, want) {
			t.Errorf("%s = %q, want %q", kind, names, want)
		}
		switch kind {
		case "sysctl":
			// The later setting wins, with its spacing folded.
			if values["vm.swappiness"] != "20" || values["net.ipv4.ip_forward"] != "1" {
				t.Errorf("sysctl values = %v", values)
			}
		case "timers":
			var got struct{ Attrs map[string]any }
			if err := json.Unmarshal([]byte(values["backup"]), &got); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"name": "backup", "on_calendar": "daily", "command": "/usr/local/bin/backup.sh", "user": "deploy", "description": "Nightly backup", "persistent": true}
			if !reflect.DeepEqual(got.Attrs, want) {
				t.Errorf("timer = %v, want %v", got.Attrs, want)
			}
		default:
			if values != nil {
				t.Errorf("%s has values %v", kind, values)
			}
		}
	}
}

// What the host refuses comes back as the error, and so does a kind no
// step lists or a host that can't be reached.
func TestListHostSurfacesFailures(t *testing.T) {
	broken := (&unitScripts{}).on("", "!the host broke")
	conn := cty.ObjectVal(unitHost(t, broken.answer))
	for _, kind := range []string{"packages", "services", "users", "mounts"} {
		if _, _, err := ListHost(ctx, kind, conn); err == nil {
			t.Errorf("%s listed on a broken host", kind)
		}
	}
	// A family the package steps don't manage stops at detection.
	arch := cty.ObjectVal(unitHost(t, (&unitScripts{}).on("cat /etc/os-release", "ID=arch\n").answer))
	if _, _, err := ListHost(ctx, "packages", arch); err == nil || !strings.Contains(err.Error(), "arch is not supported") {
		t.Errorf("arch: %v", err)
	}
	// So does a package list the provider can't read.
	torn := cty.ObjectVal(unitHost(t, (&unitScripts{}).on("cat /etc/os-release", "ID=rocky\n").on("rpm -qa", "!rpm: database locked").answer))
	if _, _, err := ListHost(ctx, "packages", torn); err == nil {
		t.Error("listed packages rpm refused")
	}
	if _, _, err := ListHost(ctx, "printers", conn); err == nil || !strings.Contains(err.Error(), `can't list "printers"`) {
		t.Errorf("printers: %v", err)
	}
	away := unitHost(t, broken.answer)
	away["private_key_file"] = cty.StringVal(filepath.Join(t.TempDir(), "missing"))
	if _, _, err := ListHost(ctx, "users", cty.ObjectVal(away)); err == nil {
		t.Error("listed users over a login with a missing key")
	}
}

// The Windows kinds ask the inventory script, by the kind without its
// prefix, and a failed script is the error.
func TestListHostWindowsKinds(t *testing.T) {
	h := newWinFakeHost(t)
	h.on("read_inventory.ps1", map[string]any{"names": []string{"Web-Server", "DNS"}})
	names, _, err := ListHost(ctx, "windows_features", h.conn)
	if err != nil || !reflect.DeepEqual(names, []string{"DNS", "Web-Server"}) {
		t.Fatalf("features = %q, %v", names, err)
	}
	if sent := h.sent("read_inventory.ps1"); len(sent) != 1 || sent[0]["kind"] != "features" {
		t.Errorf("sent %v", sent)
	}
	h.fail("read_inventory.ps1", "Get-WindowsFeature isn't on this edition")
	if _, _, err := ListHost(ctx, "windows_users", h.conn); err == nil || !strings.Contains(err.Error(), "Get-WindowsFeature") {
		t.Errorf("a failed script: %v", err)
	}
}
