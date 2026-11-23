// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package repo

import (
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
)

func TestSUSEFiles(t *testing.T) {
	r := Repo{Name: "shells", URL: "https://download.opensuse.org/repositories/shells/15.6/", Key: key, Priority: 90}
	if err := r.Validate(pkg.SUSE); err != nil {
		t.Fatal(err)
	}
	files := r.Files(pkg.SUSE)
	if got := files["/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-shells"]; got != key {
		t.Fatalf("key file = %q", got)
	}
	want := "# Managed by Conn3x.\n[shells]\nname=shells\nbaseurl=https://download.opensuse.org/repositories/shells/15.6/\nenabled=1\nautorefresh=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-shells\ntype=rpm-md\npriority=90\n"
	if got := files["/etc/zypp/repos.d/shells.repo"]; got != want {
		t.Fatalf("repo file = %q", got)
	}
	if len(files) != 2 {
		t.Fatalf("files = %v", files)
	}
	r.Priority = 0
	if got := r.Files(pkg.SUSE)["/etc/zypp/repos.d/shells.repo"]; strings.Contains(got, "priority") {
		t.Fatalf("no priority, but %q", got)
	}
}

// dnf reads priority from the same line; apt has none, so it's refused.
func TestPriority(t *testing.T) {
	r := Repo{Name: "x", URL: "https://example.com/r", Key: key, Suites: []string{"noble"}, Priority: 10}
	if got := r.Files(pkg.RPM)["/etc/yum.repos.d/x.repo"]; !strings.HasSuffix(got, "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-x\npriority=10\n") {
		t.Errorf("dnf file = %q", got)
	}
	if err := r.Validate(pkg.Deb); err == nil || !strings.Contains(err.Error(), "priority is for dnf and zypper") {
		t.Errorf("apt with a priority: %v", err)
	}
	r.Priority = -1
	if r.Validate(pkg.SUSE) == nil {
		t.Error("a negative priority passed")
	}
}

// Apply on SUSE imports the key, then refreshes only this repository;
// Delete removes the two files and leaves rpm's keyring, as on the Red Hat
// family, whose dnf imports the key on first use.
func TestSUSEApplyAndDelete(t *testing.T) {
	r := Repo{Name: "shells", URL: "https://download.opensuse.org/repositories/shells/15.6/", Key: key}
	d := &disk{}
	if err := Apply(ctx, d, pkg.SUSE, r); err != nil {
		t.Fatal(err)
	}
	last := d.ran[len(d.ran)-2:]
	if !slices.Equal(last, []string{"rpm --import '/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-shells'", "zypper --non-interactive refresh 'shells'"}) {
		t.Errorf("Apply ended with %q", last)
	}
	if !d.ranAny("/etc/zypp/repos.d/shells.repo") {
		t.Error("no .repo file written")
	}
	if err := Apply(ctx, &disk{fail: "zypper --non-interactive refresh"}, pkg.SUSE, r); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("a failed refresh: %v", err)
	}
	d = &disk{}
	if err := Delete(ctx, d, pkg.SUSE, r); err != nil {
		t.Fatal(err)
	}
	if d.ranAny("rpm -e") || d.ranAny("zypper") || !d.ranAny("/etc/zypp/repos.d/shells.repo") {
		t.Errorf("Delete ran %q", d.ran)
	}
}

// openSUSE's own files are repo-*.repo, owned by openSUSE-release or by
// nothing; a zypper service's carry service=, which the listing marks.
func TestSUSESourcesUnlisted(t *testing.T) {
	if s := listScript(pkg.SUSE); !strings.Contains(s, "cd '/etc/zypp/repos.d'") || !strings.Contains(s, "^service=") {
		t.Errorf("listScript:\n%s", s)
	}
	files := []SourceFile{
		{Name: "repo-oss.repo"},
		{Name: "repo-sle-update.repo", Owners: []string{"openSUSE-release"}},
		{Name: "SLES15-SP6-Pool.repo", Owners: []string{zypperService}},
		{Name: "shells.repo", Marked: true},
		{Name: "packman.repo"},
	}
	got, err := Sources{}.Unlisted(pkg.SUSE, "opensuse-leap", files)
	if err != nil || !slices.Equal(got, []string{"packman.repo"}) {
		t.Errorf("Unlisted: %q, %v", got, err)
	}
}
