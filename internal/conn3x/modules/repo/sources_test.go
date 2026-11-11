// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package repo

import (
	"slices"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
)

// The distribution's files, Conn3x's and keep stay; everything else goes,
// and remove takes a distribution file but never a marked one.
func TestSourcesUnlisted(t *testing.T) {
	id, rocky, err := parseSources("rocky\x00docker-ce.repo\x001\x00\x00epel.repo\x000\x00epel-release \x00rocky.repo\x000\x00rocky-repos \x00rocky-devel.repo\x000\x00rocky-repos \x00mine.repo\x000\x00\x00")
	if err != nil || id != "rocky" || len(rocky) != 5 || !rocky[0].Marked || rocky[2].Owners[0] != "rocky-repos" {
		t.Fatalf("parseSources: %q %+v %v", id, rocky, err)
	}
	for _, tc := range []struct {
		name   string
		family pkg.Family
		id     string
		files  []SourceFile
		s      Sources
		want   []string
	}{
		{"rocky", pkg.RPM, "rocky", rocky, Sources{}, []string{"epel.repo", "mine.repo"}},
		{"keep and remove", pkg.RPM, "rocky", rocky, Sources{Keep: []string{"epel.repo"}, Remove: []string{"rocky-devel.repo"}}, []string{"rocky-devel.repo", "mine.repo"}},
		{"fedora-repos-modular", pkg.RPM, "fedora", []SourceFile{{Name: "fedora-modular.repo", Owners: []string{"fedora-repos-modular"}}}, Sources{}, nil},
		{"rhel", pkg.RPM, "rhel", []SourceFile{{Name: "redhat.repo"}, {Name: "x.repo"}}, Sources{}, []string{"x.repo"}},
		{"ubuntu", pkg.Deb, "ubuntu", []SourceFile{{Name: "ubuntu.sources"}, {Name: "ubuntu-esm-apps.sources"}, {Name: "docker.sources", Marked: true}, {Name: "old.list"}}, Sources{}, []string{"ubuntu-esm-apps.sources", "old.list"}},
		{"no os-release", pkg.Deb, "", []SourceFile{{Name: ".sources"}}, Sources{}, []string{".sources"}},
	} {
		got, err := tc.s.Unlisted(tc.family, tc.id, tc.files)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := (Sources{Remove: []string{"docker-ce.repo"}}).Unlisted(pkg.RPM, "rocky", rocky); err == nil || !strings.Contains(err.Error(), "repository step wrote") {
		t.Errorf("remove naming a marked file: %v", err)
	}
	if _, _, err := parseSources("rocky\x00a.repo\x001\x00"); err == nil {
		t.Error("a short record parsed")
	}
}

func TestSourcesValidate(t *testing.T) {
	for _, bad := range []Sources{{Keep: []string{"../x"}}, {Remove: []string{"a b.list"}}, {Keep: []string{".."}}, {Keep: []string{"a.list"}, Remove: []string{"a.list"}}} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	if err := (Sources{Keep: []string{"docker.sources"}, Remove: []string{"ubuntu-esm-apps.sources"}}).Validate(); err != nil {
		t.Error(err)
	}
}
