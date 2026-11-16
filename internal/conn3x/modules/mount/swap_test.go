// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mount

import (
	"strings"
	"testing"
)

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

func TestReadSwap(t *testing.T) {
	s := Swap{Path: "/swapfile", Size: "1G", Priority: "5"}
	h := &host{fstab: s.Line() + "\n", swap: "on 5\n1073741824\n"}
	if a, err := ReadSwap(ctx, h, s); err != nil || !s.InSync(a) {
		t.Fatalf("got %+v, %v", a, err)
	}
	h.swap = "off\nlots\n"
	if _, err := ReadSwap(ctx, h, s); err == nil {
		t.Error("parsed a size that isn't a number")
	}
	h.fail = "/proc/swaps"
	if _, err := ReadSwap(ctx, h, s); err == nil || err.Error() != "boom" {
		t.Errorf("failing: %v", err)
	}
}

func TestApplySwap(t *testing.T) {
	for name, c := range map[string]struct {
		s         Swap
		want, not []string
	}{
		"file": {
			Swap{Path: "/swapfile", Size: "1G"},
			[]string{"fallocate -l 1073741824", "count=1024", "mkswap", "swapon -- \"$p\""},
			[]string{"set size", "swapon -p"},
		},
		// A device that isn't swap yet is refused, never formatted.
		"device": {
			Swap{Path: "/dev/vdb", Priority: "5"},
			[]string{"set size to make a swap file there", "run mkswap on it first", "swapon -p 5 --", "!= '5'"},
			[]string{"fallocate", "mkswap --"},
		},
	} {
		h := &host{}
		if err := ApplySwap(ctx, h, c.s); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(h.ran[0], w) {
				t.Errorf("%s: missing %q", name, w)
			}
		}
		for _, n := range c.not {
			if strings.Contains(h.ran[0], n) {
				t.Errorf("%s: has %q", name, n)
			}
		}
		if h.fstab != c.s.Line()+"\n" {
			t.Errorf("%s: fstab %q", name, h.fstab)
		}
	}
	h := &host{}
	if err := ApplySwap(ctx, h, Swap{Path: "/dev/vdb", Size: "1G"}); err == nil || len(h.ran) != 0 {
		t.Errorf("a size for a device reached the host: %v, %q", err, h.ran)
	}
	h = &host{fail: "swapon"}
	if err := ApplySwap(ctx, h, Swap{Path: "/swapfile", Size: "1G"}); err == nil || h.fstab != "" {
		t.Errorf("a failed swapon still wrote fstab: %v, %q", err, h.fstab)
	}
}

func TestDeleteSwap(t *testing.T) {
	file := Swap{Path: "/swapfile", Size: "1G"}
	h := &host{fstab: "UUID=1 / ext4 defaults 0 1\n" + file.Line() + "\n"}
	if err := DeleteSwap(ctx, h, file); err != nil {
		t.Fatal(err)
	}
	if h.fstab != "UUID=1 / ext4 defaults 0 1\n" || !h.has("swapoff") || h.ran[len(h.ran)-1] != "rm -f -- '/swapfile'" {
		t.Fatalf("fstab %q after %q", h.fstab, h.ran)
	}
	// A device is turned off and left there.
	h = &host{fstab: "/dev/vdb none swap defaults 0 0\n"}
	if err := DeleteSwap(ctx, h, Swap{Path: "/dev/vdb"}); err != nil || h.fstab != "" || h.has("rm -f -- '/dev/vdb'") {
		t.Fatalf("%v: fstab %q after %q", err, h.fstab, h.ran)
	}
	h = &host{fstab: file.Line() + "\n", fail: "swapoff"}
	if err := DeleteSwap(ctx, h, file); err == nil || h.fstab == "" || h.has("rm -f") {
		t.Fatalf("a failed swapoff went on: %v after %q", err, h.ran)
	}
}
