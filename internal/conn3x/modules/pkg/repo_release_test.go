// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func failed(stderr string) ssh.Result { return ssh.Result{ExitCode: 100, Stderr: []byte(stderr)} }

func TestValidateRepoRelease(t *testing.T) {
	for _, bad := range []Desired{
		{Name: "nasm", State: Present, EnableRepositories: []string{"crb;reboot"}},
		{Name: "nasm", State: Present, EnableRepositories: []string{"epel*"}},
		{Name: "nasm", State: Present, EnableRepositories: []string{"-crb"}},
		{Name: "nasm", State: Present, EnableRepositories: []string{""}},
		{Name: "nasm", State: Present, EnableRepositories: []string{"crb'"}},
		{Name: "tmux", State: Present, TargetRelease: "trixie backports"},
		{Name: "tmux", State: Present, TargetRelease: "$(reboot)"},
		{Name: "tmux", State: Present, TargetRelease: "-o"},
		{Name: "tmux", State: Present, TargetRelease: "a=stable"},
		{Name: "tmux", State: Present, TargetRelease: "trixie-backports", EnableRepositories: []string{"crb"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate(%+v) accepted", bad)
		}
	}
	for _, good := range []Desired{
		{Name: "nasm", State: Latest, EnableRepositories: []string{"crb", "epel-testing", "copr:copr.fedorainfracloud.org:group_x:y", "my_repo.1"}},
		{Name: "tmux", State: Present, TargetRelease: "trixie-backports"},
		{Name: "tmux", State: Present, TargetRelease: "13"},
		{Name: "tmux", State: Present, TargetRelease: "noble-updates"},
	} {
		if err := good.Validate(); err != nil {
			t.Errorf("Validate(%+v): %v", good, err)
		}
	}
}

func TestFits(t *testing.T) {
	repos := Desired{Name: "nasm", State: Present, EnableRepositories: []string{"crb"}}
	release := Desired{Name: "tmux", State: Present, TargetRelease: "trixie-backports"}
	for _, c := range []struct {
		d      Desired
		family Family
		want   string
	}{
		{repos, RPM, ""},
		{repos, Deb, "enable_repositories only applies on the Red Hat family, with dnf, and this host uses apt"},
		{repos, SUSE, "this host uses zypper"},
		{release, Deb, ""},
		{release, RPM, "target_release only applies on Debian and Ubuntu, with apt, and this host uses dnf"},
		{release, APK, "this host uses apk"},
	} {
		err := c.d.Fits(c.family)
		if (c.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v on %s: %v, want %q", c.d, c.family, err, c.want)
		}
		// Apply refuses before running anything.
		h := &scriptedHost{}
		if err := Apply(ctx, h, c.family, c.d); c.want != "" && (err == nil || len(h.ran) != 0) {
			t.Errorf("Apply %+v on %s: %v, ran %q", c.d, c.family, err, h.ran)
		}
	}
}

// The repositories and the release reach both the install and the
// newest-version query, quoted.
func TestRepoReleaseCommands(t *testing.T) {
	for _, c := range []struct {
		family Family
		d      Desired
		want   []string
	}{
		{RPM, Desired{Name: "nasm", State: Present, EnableRepositories: []string{"crb", "epel"}},
			[]string{"dnf -y --enablerepo='crb' --enablerepo='epel' install 'nasm'"}},
		{RPM, Desired{Name: "nasm", State: Latest, EnableRepositories: []string{"crb"}},
			[]string{"dnf -y --enablerepo='crb' install 'nasm'", "dnf -y --enablerepo='crb' upgrade 'nasm'"}},
		{Deb, Desired{Name: "tmux", State: Present, TargetRelease: "trixie-backports"},
			[]string{aptGet + " -t 'trixie-backports' install 'tmux'"}},
		{Deb, Desired{Name: "tmux", State: Present, TargetRelease: "trixie-backports", Source: "/opt/dl/tmux.deb"},
			[]string{inner(aptGet + " -t 'trixie-backports' --allow-downgrades install '/opt/dl/tmux.deb'")}},
		{RPM, Desired{Name: "nasm", State: Present, EnableRepositories: []string{"crb"}, Source: "/opt/dl/nasm.rpm"},
			[]string{inner("dnf -y --enablerepo='crb' install '/opt/dl/nasm.rpm'")}},
	} {
		h := &scriptedHost{answers: []answer{
			{"rpm -qp", ok("nasm 0:2.16-1.el10\n")},
			{"dpkg-deb", ok("Package: tmux\nVersion: 3.7c-1\n")},
			{"rpm -q ", failed("")},
			{"install", ok("")},
			{"upgrade", ok("")},
		}}
		if err := Apply(ctx, h, c.family, c.d); err != nil {
			t.Fatalf("%+v: %v", c.d, err)
		}
		all := strings.Join(h.ran, "\n")
		for _, w := range c.want {
			if !strings.Contains(all, w) {
				t.Errorf("%+v ran %q, want %q", c.d, h.ran, w)
			}
		}
	}

	for _, c := range []struct {
		family    Family
		d         Desired
		query, in string
		want      string
	}{
		{RPM, Desired{Name: "nasm", State: Latest, EnableRepositories: []string{"crb"}},
			"dnf -q --enablerepo='crb' repoquery --latest-limit 1", "0:2.16.01-9.el10", "0:2.16.01-9.el10"},
		{Deb, Desired{Name: "tmux", State: Latest, TargetRelease: "trixie-backports"},
			"apt-cache -t 'trixie-backports' policy -- 'tmux'", "tmux:\n  Installed: (none)\n  Candidate: 3.7c-1~bpo13+1\n", "3.7c-1~bpo13+1"},
	} {
		h := &scriptedHost{answers: []answer{{c.query, ok(c.in)}, {"", failed("")}}}
		a, err := ReadFor(ctx, h, c.family, c.d)
		if err != nil || a.Candidate != c.want {
			t.Errorf("%+v: %+v %v, ran %q", c.d, a, err, h.ran)
		}
		// Present reads only what's installed, as before.
		c.d.State = Present
		h = &scriptedHost{answers: []answer{{"", failed("")}}}
		if _, err := ReadFor(ctx, h, c.family, c.d); err != nil || strings.Contains(strings.Join(h.ran, "\n"), c.query) {
			t.Errorf("present %+v: %v, ran %q", c.d, err, h.ran)
		}
	}
}

// A host without the backports lists yet fails -t this way, and gets
// them fetched once.
func TestStaleListsRelease(t *testing.T) {
	h := &scriptedHost{answers: []answer{
		{"update", ok("")},
		{"install", failed("E: The value 'trixie-backports' is invalid for APT::Default-Release as such a release is not available in the sources")},
	}}
	_ = Apply(ctx, h, Deb, Desired{Name: "tmux", State: Present, TargetRelease: "trixie-backports"})
	if !strings.Contains(strings.Join(h.ran, "\n"), "apt-get -q -o DPkg::Lock::Timeout=300 update") {
		t.Errorf("no update after the release was missing: %q", h.ran)
	}
}
