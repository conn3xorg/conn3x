// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// inner is s as it reads inside the quotes Guard puts the script in.
func inner(s string) string { q := ssh.Quote(s); return q[1 : len(q)-1] }

func TestValidateSource(t *testing.T) {
	for _, bad := range []Desired{
		{Name: "agent", State: Present, Source: "tmp/agent.deb"},
		{Name: "agent", State: Present, Source: "/tmp/agent.tar.gz"},
		{Name: "agent", State: Present, Source: "/tmp/agent $(reboot).deb"},
		{Name: "agent", State: Present, Source: "/tmp/agent';reboot;'.rpm"},
		{Name: "agent", State: Present, Source: "/tmp/../etc/agent.deb"},
		{Name: "agent", State: Present, Source: "/tmp//agent.deb"},
		{Name: "agent", State: Present, Source: "/tmp/agent\n.deb"},
		{Name: "agent", State: Present, Source: "/tmp/agent.deb", Version: "1.4.0"},
		{Name: "agent", State: Latest, Source: "/tmp/agent.rpm"},
		{Name: "agent", State: Present, SourceSHA256: strings.Repeat("a", 64)},
		{Name: "agent", State: Present, Source: "/tmp/agent.deb", SourceSHA256: strings.Repeat("A", 64)},
		{Name: "agent", State: Present, Source: "/tmp/agent.deb", SourceSHA256: strings.Repeat("a", 63)},
		{Name: "agent", State: Present, Source: "/tmp/agent.deb", SourceSHA256: strings.Repeat("a", 63) + "'"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
	for _, good := range []Desired{
		{Name: "agent", State: Present, Source: "/tmp/agent_1.4.0-1_amd64.deb"},
		{Name: "agent", State: Present, Source: "/opt/dl/agent-1:1.4.0-1.el9.x86_64.rpm"},
		{Name: "agent", State: Absent, Source: "/tmp/agent.deb"},
		{Name: "agent", State: Present, Source: "/tmp/agent.deb", SourceSHA256: strings.Repeat("0a", 32)},
	} {
		if err := good.Validate(); err != nil {
			t.Errorf("Validate(%+v): %v", good, err)
		}
	}
}

func TestReadSource(t *testing.T) {
	for _, tc := range []struct {
		family      Family
		src, out    string
		name, ver   string
		wantCommand string
	}{
		{Deb, "/tmp/agent.deb", "Package: agent\nVersion: 1:1.4.0-1\n", "agent", "1:1.4.0-1", `dpkg-deb -f "$f" Package Version`},
		{RPM, "/tmp/agent.rpm", "agent 0:1.4.0-1.el9\n", "agent", "0:1.4.0-1.el9", "rpm -qp --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}"},
		{SUSE, "/tmp/agent.rpm", "missing\n", "", "", "rpm -qp"},
	} {
		h := &scriptedHost{answers: []answer{{"", ok(tc.out)}}}
		name, ver, err := ReadSource(ctx, h, tc.family, tc.src)
		if err != nil || name != tc.name || ver != tc.ver {
			t.Errorf("%s %s: %q %q %v", tc.family, tc.src, name, ver, err)
		}
		if !strings.Contains(h.ran[0], inner(tc.wantCommand)) || !strings.Contains(h.ran[0], inner("f='"+tc.src+"'")) {
			t.Errorf("%s ran %q", tc.family, h.ran[0])
		}
	}
	for family, src := range map[Family]string{RPM: "/tmp/agent.deb", Deb: "/tmp/agent.rpm", APK: "/tmp/agent.rpm"} {
		if _, _, err := ReadSource(ctx, &scriptedHost{}, family, src); err == nil {
			t.Errorf("%s read %s", family, src)
		}
	}
	h := &scriptedHost{answers: []answer{{"", ok("oops\n")}}}
	if _, _, err := ReadSource(ctx, h, Deb, "/tmp/agent.deb"); err == nil || !strings.Contains(err.Error(), "unexpected output") {
		t.Errorf("garbage: %v", err)
	}
}

func TestApplySource(t *testing.T) {
	for _, tc := range []struct {
		family    Family
		src       string
		installed string
		want      string
	}{
		{Deb, "/tmp/agent.deb", "", "apt-get -y -q -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --allow-downgrades install '/tmp/agent.deb'"},
		{RPM, "/tmp/agent.rpm", "", "dnf -y install '/tmp/agent.rpm'"},
		{RPM, "/tmp/agent.rpm", "0:1.3.0-1.el9", "dnf -y install '/tmp/agent.rpm'"},
		{RPM, "/tmp/agent.rpm", "0:1.5.0-1.el9", "dnf -y downgrade '/tmp/agent.rpm'"},
		{SUSE, "/tmp/agent.rpm", "", "zypper -n -q install --oldpackage --allow-unsigned-rpm '/tmp/agent.rpm'"},
	} {
		installed := ssh.Result{ExitCode: 1}
		if tc.installed != "" {
			installed = ok(tc.installed + ".x86_64\n")
		}
		h := &scriptedHost{answers: []answer{
			{"rpm -qp", ok("agent 0:1.4.0-1.el9\n")},
			{"dpkg-deb", ok("Package: agent\nVersion: 1.4.0-1\n")},
			{"rpm -q ", installed},
			{"install", ok("")},
			{"downgrade", ok("")},
		}}
		if err := Apply(ctx, h, tc.family, Desired{Name: "agent", State: Present, Source: tc.src}); err != nil {
			t.Fatalf("%s: %v", tc.family, err)
		}
		last := h.ran[len(h.ran)-1]
		if !strings.Contains(last, inner(tc.want)) || !strings.Contains(last, "route_walk whole '"+tc.src+"'") {
			t.Errorf("%s with %q installed ran %q, want %q under the whole-path guard", tc.family, tc.installed, last, tc.want)
		}
	}

	for out, want := range map[string]string{
		"missing\n":                  "source /tmp/agent.rpm doesn't exist on the host",
		"telnet 0:1.4.0-1.el9\n":     "source /tmp/agent.rpm is the package telnet, not agent",
		"agent 0:1.4.0-1.el9\n#bad ": "unexpected output",
	} {
		h := &scriptedHost{answers: []answer{{"rpm -qp", ok(out)}}}
		err := Apply(ctx, h, RPM, Desired{Name: "agent", State: Present, Source: "/tmp/agent.rpm"})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", out, err, want)
		}
		if len(h.ran) != 1 {
			t.Errorf("%q ran more than the read: %q", out, h.ran)
		}
	}

	// absent removes by name, as without source.
	h := &scriptedHost{answers: []answer{{"", ok("")}}}
	if err := Apply(ctx, h, RPM, Desired{Name: "agent", State: Absent, Source: "/tmp/agent.rpm"}); err != nil || h.ran[0] != "dnf -y remove 'agent'" {
		t.Errorf("absent ran %q, %v", h.ran, err)
	}
}

func TestNeedsChangeSource(t *testing.T) {
	d := Desired{Name: "agent", State: Present, Source: "/tmp/agent.deb"}
	for _, tc := range []struct {
		a    Actual
		want bool
	}{
		{Actual{}, true},
		{Actual{Installed: true, Version: "1.4.0-1", SourceVersion: "1.4.0-1"}, false},
		{Actual{Installed: true, Version: "1.4.0-1", SourceVersion: "1.5.0-1"}, true},
		{Actual{Installed: true, Version: "1.5.0-1", SourceVersion: "1.4.0-1"}, true},
		// The file is gone: what's installed stays.
		{Actual{Installed: true, Version: "1.4.0-1"}, false},
	} {
		if got := NeedsChange(d, tc.a); got != tc.want {
			t.Errorf("NeedsChange(%+v) = %v", tc.a, got)
		}
	}
}

// Settled reads the file too: a newer file isn't settled. A missing one
// is, with the package installed, as the plan has it; without the
// package it isn't, and Apply names the file.
func TestSettledSource(t *testing.T) {
	d := Desired{Name: "agent", State: Present, Source: "/tmp/agent.deb"}
	for _, tc := range []struct {
		installed, file string
		want            bool
	}{
		{"ii 1.4.0-1\n", "Package: agent\nVersion: 1.4.0-1\n", true},
		{"ii 1.4.0-1\n", "Package: agent\nVersion: 1.5.0-1\n", false},
		{"ii 1.4.0-1\n", "missing\n", true},
		{"", "missing\n", false},
	} {
		h := &scriptedHost{answers: []answer{{"dpkg-query", ok(tc.installed)}, {"dpkg-deb", ok(tc.file)}}}
		if got := Settled(ctx, h, Deb, d); got != tc.want {
			t.Errorf("installed %q, file %q: Settled = %v", tc.installed, tc.file, got)
		}
	}
}

// With source_sha256, the install checks the file's hash first, in the
// same guarded script, so it installs only the file that was checked. A
// file with another hash isn't settled, so Apply gets to refuse it.
func TestSourceSHA256(t *testing.T) {
	want, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	d := Desired{Name: "agent", State: Present, Source: "/tmp/agent.deb", SourceSHA256: want}
	h := &scriptedHost{answers: []answer{
		{"dpkg-deb", ok("Package: agent\nVersion: 1.4.0-1\n")},
		{"install", ok("")},
	}}
	if err := Apply(ctx, h, Deb, d); err != nil {
		t.Fatal(err)
	}
	last := h.ran[len(h.ran)-1]
	check := strings.Index(last, inner(`[ "$got" = `+want+` ] || {`))
	install := strings.Index(last, inner("--allow-downgrades install '/tmp/agent.deb'"))
	if check < 0 || install < check || !strings.Contains(last, "route_walk whole '/tmp/agent.deb'") || !strings.Contains(last, "refusing to install it") {
		t.Errorf("install doesn't check the hash first under the guard: %q", last)
	}

	for sum, settled := range map[string]bool{want: true, other: false, "": false} {
		h := &scriptedHost{answers: []answer{
			{"dpkg-query", ok("ii 1.4.0-1\n")},
			{"dpkg-deb", ok("Package: agent\nVersion: 1.4.0-1\n")},
			{"sum256", ok(sum + "\n")},
		}}
		if got := Settled(ctx, h, Deb, d); got != settled {
			t.Errorf("file hashing to %q: Settled = %v", sum, got)
		}
	}
	h = &scriptedHost{answers: []answer{{"sum256", ok(other + "\n")}}}
	if got, err := SourceSum(ctx, h, "/tmp/agent.deb"); err != nil || got != other {
		t.Errorf("SourceSum = %q, %v", got, err)
	}
	h = &scriptedHost{answers: []answer{{"sum256", ok("nope\n")}}}
	if _, err := SourceSum(ctx, h, "/tmp/agent.deb"); err == nil {
		t.Error("SourceSum took garbage")
	}
}
