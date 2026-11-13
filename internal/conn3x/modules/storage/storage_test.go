// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// fakeDisk answers the scripts this package runs as one device and one
// volume group would.
type fakeDisk struct {
	fsType, mountedAt string
	devSize, fsSize   int64
	lvExists          bool
	lvSize, extent    int64
	vgSize            int64
	ran               []string
}

// unwrap undoes the quoting GuardRoot's sh -c adds, so tests can look
// for the commands as written.
func unwrap(cmd string) string { return strings.ReplaceAll(cmd, `'\''`, "'") }

func (h *fakeDisk) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	cmd = unwrap(cmd)
	h.ran = append(h.ran, cmd)
	var out string
	switch {
	case strings.Contains(cmd, `echo "type=$t"`):
		out = fmt.Sprintf("type=%s\ndevsize=%d\nmounted=%s\n", h.fsType, h.devSize, h.mountedAt)
		if strings.Contains(cmd, "dumpe2fs") {
			out += fmt.Sprintf("size=%d\n", h.fsSize)
		}
	case strings.Contains(cmd, "mkfs.") || strings.Contains(cmd, "mkswap"):
		for _, t := range FilesystemTypes() {
			if strings.Contains(cmd, "mkfs."+t+" ") || (t == "swap" && strings.Contains(cmd, "mkswap")) {
				h.fsType, h.fsSize = t, h.devSize
			}
		}
	case strings.Contains(cmd, "resize2fs") || strings.Contains(cmd, "xfs_growfs"):
		h.fsSize = h.devSize
	case strings.Contains(cmd, "vg_extent_size"):
		out = fmt.Sprintf("extent=%d\nvgsize=%d\n", h.extent, h.vgSize)
		if h.lvExists {
			out += fmt.Sprintf("exists=1\nsize=%d\n", h.lvSize)
		}
	case strings.Contains(cmd, "lvcreate"), strings.Contains(cmd, "lvextend"), strings.Contains(cmd, "lvreduce"):
		h.lvExists, h.lvSize = true, 2<<30
	}
	return ssh.Result{Stdout: []byte(out)}, nil
}

func (h *fakeDisk) ranAny(s string) bool {
	for _, c := range h.ran {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

var ctx = context.Background()

func TestFilesystemMakesOnAnEmptyDevice(t *testing.T) {
	h := &fakeDisk{devSize: 10 << 30}
	if err := ApplyFilesystem(ctx, h, Filesystem{Device: "/dev/vg0/data", Type: "ext4", Opts: []string{"-L", "data"}}); err != nil {
		t.Fatal(err)
	}
	if !h.ranAny("mkfs.ext4 -q '-L' 'data' '/dev/vg0/data'") || h.ranAny("-q -F") {
		t.Errorf("ran %q", h.ran)
	}
}

func TestFilesystemWontEraseWithoutForce(t *testing.T) {
	h := &fakeDisk{fsType: "xfs", devSize: 10 << 30}
	f := Filesystem{Device: "/dev/sdb", Type: "ext4"}
	if err := ApplyFilesystem(ctx, h, f); err == nil || !strings.Contains(err.Error(), "already holds a xfs file system") || !strings.Contains(err.Error(), "force = true") || h.ranAny("mkfs") {
		t.Fatalf("err = %v, ran %q", err, h.ran)
	}
	h = &fakeDisk{fsType: "LVM2_member", devSize: 10 << 30}
	if err := ApplyFilesystem(ctx, h, f); err == nil || !strings.Contains(err.Error(), "an LVM physical volume") {
		t.Fatalf("a PV: %v", err)
	}
	f.Force = true
	h = &fakeDisk{fsType: "xfs", devSize: 10 << 30, mountedAt: "/srv"}
	if err := ApplyFilesystem(ctx, h, f); err == nil || !strings.Contains(err.Error(), "mounted at /srv") || h.ranAny("mkfs") {
		t.Fatalf("mounted, with force: %v", err)
	}
	h = &fakeDisk{fsType: "xfs", devSize: 10 << 30}
	if err := ApplyFilesystem(ctx, h, f); err != nil || !h.ranAny("mkfs.ext4 -q -F '/dev/sdb'") {
		t.Fatalf("with force: %v, ran %q", err, h.ran)
	}
}

func TestFilesystemResize(t *testing.T) {
	f := Filesystem{Device: "/dev/vg0/data", Type: "ext4", Resize: true}
	if !f.InSync(FilesystemActual{Type: "ext4", DeviceSize: 10 << 30, Size: 10<<30 - 4096}) {
		t.Error("a file system short of its device by one block should be in sync")
	}
	h := &fakeDisk{fsType: "ext4", devSize: 20 << 30, fsSize: 10 << 30}
	if err := ApplyFilesystem(ctx, h, f); err != nil || !h.ranAny("e2fsck -f -p '/dev/vg0/data' && resize2fs '/dev/vg0/data'") {
		t.Fatalf("unmounted ext4: %v, ran %q", err, h.ran)
	}
	h = &fakeDisk{fsType: "ext4", devSize: 20 << 30, fsSize: 10 << 30, mountedAt: "/srv"}
	if err := ApplyFilesystem(ctx, h, f); err != nil || h.ranAny("e2fsck") || !h.ranAny("resize2fs '/dev/vg0/data'") {
		t.Fatalf("mounted ext4: %v, ran %q", err, h.ran)
	}
	f.Type = "xfs"
	h = &fakeDisk{fsType: "xfs", devSize: 20 << 30, fsSize: 10 << 30}
	if err := f.grow(ctx, h, FilesystemActual{Type: "xfs", DeviceSize: 20 << 30, Size: 10 << 30}); err == nil || !strings.Contains(err.Error(), "only while mounted") {
		t.Fatalf("unmounted xfs: %v", err)
	}
	if err := f.grow(ctx, h, FilesystemActual{Type: "xfs", DeviceSize: 20 << 30, Size: 10 << 30, MountedAt: "/srv"}); err != nil || !h.ranAny("xfs_growfs '/srv'") {
		t.Fatalf("mounted xfs: %v, ran %q", err, h.ran)
	}
}

func TestStorageValidate(t *testing.T) {
	for _, f := range []Filesystem{
		{Device: "/dev/sdb; rm -rf /", Type: "ext4"},
		{Device: "sdb", Type: "ext4"},
		{Device: "/dev/../etc/passwd", Type: "ext4"},
		{Device: "/dev/sdb", Type: "ntfs"},
		{Device: "/dev/sdb", Type: "vfat", Resize: true},
		{Device: "/dev/sdb", Type: "ext4", Opts: []string{"-L data"}},
	} {
		if f.Validate() == nil {
			t.Errorf("%+v should be refused", f)
		}
	}
	for _, g := range []VolumeGroup{{Name: "-vg", PVs: []string{"/dev/sdb"}}, {Name: "vg0"}, {Name: "vg0", PVs: []string{"/tmp/x"}}} {
		if g.Validate() == nil {
			t.Errorf("%+v should be refused", g)
		}
	}
	for _, size := range []string{"0", "10x", "101%VG", "0%FREE", "50%ORIGIN", "-1g"} {
		if (LogicalVolume{VG: "vg0", Name: "data", Size: size}).Validate() == nil {
			t.Errorf("size %q should be refused", size)
		}
	}
	for _, size := range []string{"512", "512m", "20G", "1.5t", "50%VG", "100%FREE"} {
		if err := (LogicalVolume{VG: "vg0", Name: "data", Size: size}).Validate(); err != nil {
			t.Errorf("size %q: %v", size, err)
		}
	}
}

func TestLogicalVolumeTarget(t *testing.T) {
	a := LogicalVolumeActual{ExtentSize: 32 << 20, VGSize: 10 << 30}
	for size, want := range map[string]int64{"1g": 1 << 30, "100m": 128 << 20, "100": 128 << 20, "50%VG": 5 << 30, "100%FREE": 0} {
		if got := (LogicalVolume{Size: size}).Target(a); got != want {
			t.Errorf("%s = %d, want %d", size, got, want)
		}
	}
}

func TestLogicalVolumeApply(t *testing.T) {
	l := LogicalVolume{VG: "vg0", Name: "data", Size: "2g"}
	h := &fakeDisk{extent: 4 << 20, vgSize: 10 << 30}
	if err := ApplyLogicalVolume(ctx, h, l); err != nil || !h.ranAny("lvcreate -y -W y -n 'data' -L '2g' -- 'vg0'") {
		t.Fatalf("create: %v, ran %q", err, h.ran)
	}
	h = &fakeDisk{extent: 4 << 20, vgSize: 10 << 30, lvExists: true, lvSize: 1 << 30}
	if err := ApplyLogicalVolume(ctx, h, l); err != nil || !h.ranAny("lvextend -L '2g' -- 'vg0/data'") {
		t.Fatalf("grow: %v, ran %q", err, h.ran)
	}
	h = &fakeDisk{extent: 4 << 20, vgSize: 10 << 30, lvExists: true, lvSize: 3 << 30}
	if err := ApplyLogicalVolume(ctx, h, l); err == nil || !strings.Contains(err.Error(), "is 3 GiB, bigger than its size 2g") || h.ranAny("lvreduce") {
		t.Fatalf("shrink without force: %v, ran %q", err, h.ran)
	}
	l.Force = true
	if err := ApplyLogicalVolume(ctx, h, l); err != nil || !h.ranAny("lvreduce -f -L '2g' -- 'vg0/data'") {
		t.Fatalf("shrink with force: %v, ran %q", err, h.ran)
	}
	free := LogicalVolume{VG: "vg0", Name: "rest", Size: "100%FREE"}
	if !free.InSync(LogicalVolumeActual{Exists: true, Size: 1 << 30, ExtentSize: 4 << 20}) {
		t.Errorf("a 100%%FREE volume that exists should be in sync")
	}
}

func TestVolumeGroupScripts(t *testing.T) {
	g := VolumeGroup{Name: "vg0", PVs: []string{"/dev/sdb", "/dev/disk/by-id/x"}}
	h := &recorder{}
	if err := ApplyVolumeGroup(ctx, h, g); err == nil {
		t.Fatal("the recorder never reports the group, so the read-back should fail")
	}
	create := h.ran[1]
	if !strings.Contains(create, "vgcreate -- 'vg0' '/dev/sdb' '/dev/disk/by-id/x'") || !strings.Contains(create, "force = true") {
		t.Errorf("create without force: %s", create)
	}
	g.Force, h.ran = true, nil
	_ = ApplyVolumeGroup(ctx, h, g)
	if create := h.ran[1]; !strings.Contains(create, "vgcreate -y -- 'vg0'") || strings.Contains(create, "force = true") || !strings.Contains(create, "is already in volume group") {
		t.Errorf("create with force: %s", create)
	}
}

// recorder succeeds at everything and prints nothing.
type recorder struct{ ran []string }

func (h *recorder) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, unwrap(cmd))
	return ssh.Result{}, nil
}
