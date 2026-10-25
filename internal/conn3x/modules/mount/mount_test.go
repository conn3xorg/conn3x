// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mount

import "testing"

func TestValidate(t *testing.T) {
	for _, ok := range []Mount{
		{Path: "/mnt/scratch", Src: "tmpfs", FSType: "tmpfs", Opts: "size=16m,mode=0755"},
		{Path: "/data", Src: "UUID=0a1b2c3d-1111-2222-3333-444455556666", FSType: "xfs"},
		{Path: "/srv/nfs", Src: "nfs.example.com:/export", FSType: "nfs4", Opts: "_netdev"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", ok, err)
		}
	}
	for _, bad := range []Mount{
		{Path: "relative", Src: "tmpfs", FSType: "tmpfs"},
		{Path: "/", Src: "tmpfs", FSType: "tmpfs"},
		{Path: "/mnt/a b", Src: "tmpfs", FSType: "tmpfs"},
		{Path: "/mnt/a", Src: "", FSType: "tmpfs"},
		{Path: "/mnt/a", Src: "tmpfs", FSType: "tmp fs"},
		{Path: "/mnt/a", Src: "tmpfs", FSType: "tmpfs", Opts: "size=1m\n/dev/sda1 / ext4"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestLine(t *testing.T) {
	if got := (Mount{Path: "/mnt/scratch", Src: "tmpfs", FSType: "tmpfs"}).Line(); got != "tmpfs /mnt/scratch tmpfs defaults 0 0" {
		t.Fatalf("got %q", got)
	}
}

func TestFstabLine(t *testing.T) {
	fstab := "# comment\nUUID=abc / xfs defaults 0 0\ntmpfs\t/mnt/scratch  tmpfs size=8m 0 0\n"
	if got := fstabLine(fstab, "/mnt/scratch"); got != "tmpfs /mnt/scratch tmpfs size=8m 0 0" {
		t.Fatalf("got %q", got)
	}
	if got := fstabLine(fstab, "/mnt"); got != "" {
		t.Fatalf("matched a prefix: %q", got)
	}
}
