// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package pkg

import (
	"slices"
	"testing"
)

// Every case is what rpm.vercmp answered on Rocky Linux 10.
func TestRpmvercmpMatchesRpm(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1", 1},
		{"5.5p1", "5.5p2", -1},
		{"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10.1", -1},
		{"xyz.4", "8", -1},
		{"xyz.4", "2", -1},
		{"5.5p2", "5.6p1", -1},
		{"6.0.rc1", "6.0", 1},
		{"10b2", "10a1", 1},
		{"1.0aa", "1.0a", 1},
		{"10.0001", "10.0039", -1},
		{"4.999.9", "5.0", -1},
		{"20101121", "20101122", -1},
		{"2_0", "2_0", 0},
		{"2.0", "2_0", 0},
		{"a", "b", -1},
		{"b", "a", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		{"1.0^", "1.0", 1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.01", -1},
		{"1.0^git1~pre", "1.0^git1", -1},
		{"1.0", "1.0^git1", -1},
		{"5.14.0-570.el10", "5.14.0-503.el10", 1},
		{"0", "00", 0},
		{"1.a", "a.1", 1},
		{"1", "a", 1},
		{"abc", "123", -1},
	} {
		if got := rpmvercmp(tc.a, tc.b); got != tc.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// A foreign architecture goes under each family's own form of the name, and
// several versions of one name come oldest first.
func TestParseInventory(t *testing.T) {
	deb, err := parseInventory(Deb, "amd64\nlibc6\tamd64\t2.39-0ubuntu8\nlibc6\ti386\t2.39-0ubuntu8\ntzdata\tall\t2024a-3\n")
	if err != nil || !slices.Equal(deb["libc6"], []string{"2.39-0ubuntu8"}) || !slices.Equal(deb["libc6:i386"], []string{"2.39-0ubuntu8"}) || deb["tzdata"] == nil || len(deb) != 3 {
		t.Errorf("deb: %v %v", deb, err)
	}
	rpm, err := parseInventory(RPM, "x86_64\nkernel\tx86_64\t0:5.14.0-570.el10\nkernel\tx86_64\t0:5.14.0-503.el10\nglibc\ti686\t0:2.39-17.el10\nbash\tx86_64\t0:5.2.26-6.el10\ngpg-pubkey\t(none)\t0:6fedfc85-66d7b41f\nfilesystem\tnoarch\t0:3.18-17.el10\n")
	if err != nil || !slices.Equal(rpm["kernel"], []string{"0:5.14.0-503.el10", "0:5.14.0-570.el10"}) || rpm["glibc.i686"] == nil || rpm["glibc"] != nil || rpm["gpg-pubkey"] == nil || rpm["filesystem"] == nil {
		t.Errorf("rpm: %v %v", rpm, err)
	}
	if _, err := parseInventory(RPM, "x86_64\nbroken line\n"); err == nil {
		t.Error("a line without tabs parsed")
	}
	if c := rpmCompare("1:1.0-1", "0:9.9-9"); c != 1 {
		t.Errorf("the epoch didn't decide: %d", c)
	}
}
