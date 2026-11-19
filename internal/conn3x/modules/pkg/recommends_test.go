// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import "testing"

// The option is only on the command line when InstallRecommends is set.
func TestRecommends(t *testing.T) {
	yes, no := true, false
	for _, c := range []struct {
		family Family
		set    *bool
		want   string
	}{
		{Deb, nil, ""},
		{Deb, &no, " -o APT::Install-Recommends=no"},
		{Deb, &yes, " -o APT::Install-Recommends=yes"},
		{RPM, nil, ""},
		{RPM, &no, " --setopt=install_weak_deps=False"},
		{RPM, &yes, " --setopt=install_weak_deps=True"},
	} {
		if got := (Desired{Name: "x", InstallRecommends: c.set}).recommends(c.family); got != c.want {
			t.Errorf("%v %v: %q, want %q", c.family, c.set, got, c.want)
		}
	}
}
