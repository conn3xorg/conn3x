// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestHeldIn(t *testing.T) {
	dnf4 := "\n# Added lock on Sat Nov 14 04:52:35 2026\nbash-0:5.2.26-6.el10.*\npython3-libs-0:3.12.9-1.el10.*\n"
	dnf5 := "# Added by 'versionlock add' command on 2026-11-14 04:52:16\nPackage name: bash\nevr = 5.3.15-2.fc45\n"
	for _, c := range []struct {
		family    Family
		out, name string
		want      bool
	}{
		{RPM, dnf4, "bash", true},
		{RPM, dnf4, "python3-libs", true},
		{RPM, dnf4, "python3", false},
		{RPM, dnf5, "bash", true},
		{RPM, dnf5, "bas", false},
		{RPM, "", "bash", false},
		{Deb, "bash\nlinux-image-amd64\n", "linux-image-amd64", true},
		{Deb, "bash\n", "bas", false},
	} {
		if got := heldIn(c.family, c.out, c.name); got != c.want {
			t.Errorf("%s %q in %q: %v", c.family, c.name, c.out, got)
		}
	}
	if (Hold{Name: "x-"}).Validate() == nil || (Hold{Name: "bash; rm"}).Validate() == nil {
		t.Error("a bad name passed")
	}
}

// dnf versionlock exits 0 for a name it can't find, so apply reads the list
// back rather than report a hold that isn't there.
func TestApplyHoldReadsTheListBack(t *testing.T) {
	ignored := &scriptedHost{answers: []answer{
		{"rpm -q", ok("0:1.0-1.fc45.x86_64\n")},
		{"versionlock add", ok("No package found for \"postgresqll\".\n")},
		{"versionlock list", ok("")},
	}}
	if err := ApplyHold(ctx, ignored, RPM, Hold{Name: "postgresqll", Held: true}); err == nil || !strings.Contains(err.Error(), "didn't change") {
		t.Fatalf("a hold dnf ignored: err = %v", err)
	}
	took := &scriptedHost{answers: []answer{
		{"rpm -q", ok("0:5.3.15-2.fc45.x86_64\n")},
		{"versionlock add", ok("")},
		{"versionlock list", ok("Package name: bash\nevr = 5.3.15-2.fc45\n")},
	}}
	if err := ApplyHold(ctx, took, RPM, Hold{Name: "bash", Held: true}); err != nil {
		t.Fatal(err)
	}
}

// A hold needs the package installed; releasing one that isn't is fine.
func TestApplyHoldNeedsThePackageInstalled(t *testing.T) {
	for _, family := range []Family{RPM, Deb} {
		h := &scriptedHost{answers: []answer{
			{"rpm -q", ssh.Result{ExitCode: 1}},
			{"dpkg-query", ssh.Result{ExitCode: 1}},
			{"versionlock", ok("")},
			{"apt-mark", ok("")},
		}}
		err := ApplyHold(ctx, h, family, Hold{Name: "tmux", Held: true})
		if err == nil || !strings.Contains(err.Error(), "tmux isn't installed") {
			t.Fatalf("%s: err = %v", family, err)
		}
		for _, cmd := range h.ran {
			if strings.Contains(cmd, "versionlock add") || strings.Contains(cmd, "apt-mark hold") {
				t.Fatalf("%s: ran %q anyway", family, cmd)
			}
		}
		if err := ApplyHold(ctx, h, family, Hold{Name: "tmux"}); err != nil {
			t.Fatalf("%s: releasing a package that isn't installed: %v", family, err)
		}
	}
}
