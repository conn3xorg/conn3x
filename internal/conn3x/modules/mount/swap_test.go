// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mount

import "testing"

func TestSwapValidate(t *testing.T) {
	for _, ok := range []Swap{{Path: "/swapfile", Size: "2G"}, {Path: "/dev/vdb"}, {Path: "/swapfile", Size: "512M", Priority: "-1"}} {
		if err := ok.Validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for _, bad := range []Swap{
		{Path: "swapfile", Size: "1G"},
		{Path: "/swap file", Size: "1G"},
		{Path: "/swapfile/", Size: "1G"},
		{Path: "/swapfile", Size: "1.5G"},
		{Path: "/swapfile", Size: "2048"},
		{Path: "/dev/vdb", Size: "1G"},
		{Path: "/swapfile", Size: "1G", Priority: "40000"},
		{Path: "/swapfile", Size: "1G", Priority: "high"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestSwapLineAndBytes(t *testing.T) {
	if got := (Swap{Path: "/swapfile", Size: "2G"}).Line(); got != "/swapfile none swap defaults 0 0" {
		t.Errorf("line %q", got)
	}
	if got := (Swap{Path: "/swapfile", Priority: "10"}).Line(); got != "/swapfile none swap pri=10 0 0" {
		t.Errorf("line %q", got)
	}
	if b := (Swap{Size: "512M"}).Bytes(); b != 512<<20 {
		t.Errorf("bytes %d", b)
	}
	fstab := "UUID=1 / ext4 defaults 0 1\n#/swapfile none swap sw 0 0\n/swapfile   none  swap  sw  0  0\n"
	if got := swapLine(fstab, "/swapfile"); got != "/swapfile none swap sw 0 0" {
		t.Errorf("swapLine %q", got)
	}
}

func TestSwapInSync(t *testing.T) {
	s := Swap{Path: "/swapfile", Size: "1G", Priority: "5"}
	a, err := parseSwapState(SwapActual{Entry: s.Line()}, "on 5\n1073741824\n")
	if err != nil || !s.InSync(a) {
		t.Fatalf("%+v %v", a, err)
	}
	for out, why := range map[string]string{"off\n1073741824\n": "off", "on -2\n1073741824\n": "priority", "on 5\n536870912\n": "size"} {
		a, err := parseSwapState(SwapActual{Entry: s.Line()}, out)
		if err != nil || s.InSync(a) {
			t.Errorf("%s: in sync with %+v, %v", why, a, err)
		}
	}
	if _, err := parseSwapState(SwapActual{}, "garbage"); err == nil {
		t.Error("parsed garbage")
	}
}
