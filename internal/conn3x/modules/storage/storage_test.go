// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"fmt"
	"slices"
	"strconv"
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

func TestPartition(t *testing.T) {
	p := Partition{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "100%", Label: "gpt", Flags: []string{"lvm"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	// parted -m -s /dev/vdb unit B print, on a 10 GiB disk.
	out := "BYT;\n/dev/vdb:10737418240B:virtblk:512:512:gpt:Virtio Block Device:;\n1:1048576B:10736369663B:10735321088B::primary:lvm;\n--\nLVM2_member\n"
	a, err := parsePartition(out, 1)
	if err != nil || !a.Exists || a.Table != "gpt" || a.Signature != "LVM2_member" || !slices.Equal(a.Numbers, []int{1}) {
		t.Fatalf("parsed %+v, %v", a, err)
	}
	if !p.InSync(a) {
		t.Errorf("100%% to the backup GPT should be in sync: %+v", a)
	}
	half := p
	half.End = "5GiB"
	if half.InSync(a) {
		t.Error("a whole-disk partition matched 5GiB")
	}
	noFlag := p
	noFlag.Flags = []string{}
	if noFlag.InSync(a) {
		t.Error("an lvm flag matched no flags")
	}
	blank, _ := parsePartition("BYT;\n/dev/vdb:10737418240B:virtblk:512:512:unknown:Virtio Block Device:;\n--\n", 1)
	if blank.Table != "" || blank.Exists || blank.nextFree() != 1 {
		t.Errorf("blank disk: %+v", blank)
	}
	two, _ := parsePartition("BYT;\n/dev/vdb:10737418240B:virtblk:512:512:gpt:x:;\n1:1048576B:5368709119B:5367660544B::a:;\n3:6442450944B:7516192767B:1073741824B::c:;\n--\n", 2)
	if two.nextFree() != 2 || two.Exists {
		t.Errorf("gap at 2: %+v", two)
	}
	for _, bad := range []Partition{
		{Device: "vdb", Number: 1, Start: "1MiB", End: "100%", Label: "gpt"},
		{Device: "/dev/vdb", Number: 0, Start: "1MiB", End: "100%", Label: "gpt"},
		{Device: "/dev/vdb", Number: 1, Start: "1M", End: "100%", Label: "gpt"},
		{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "101%", Label: "gpt"},
		{Device: "/dev/vdb", Number: 5, Start: "1MiB", End: "100%", Label: "msdos"},
		{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "100%", Label: "gpt", Flags: []string{"fast"}},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// fakeParted answers parted as one 10 GiB disk would: its label, its
// partitions and their flags, changed by the commands ApplyPartition runs.
type fakeParted struct {
	table string
	parts map[int][2]int64 // start and end, in bytes, end inclusive
	flags map[int][]string
	keep  bool   // mkpart makes nothing, as when parted fails quietly
	fail  string // a command holding this exits 1, printing nothing
	ran   []string
}

const disk = 10 << 30

func (h *fakeParted) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	cmd = unwrap(cmd)
	h.ran = append(h.ran, cmd)
	if h.fail != "" && strings.Contains(cmd, h.fail) {
		return ssh.Result{ExitCode: 1}, nil
	}
	if strings.Contains(cmd, "unit B print") {
		table := h.table
		if table == "" {
			table = "unknown"
		}
		out := fmt.Sprintf("BYT;\n/dev/vdb:%dB:virtblk:512:512:%s:Virtio Block Device:;\n", disk, table)
		for n, p := range h.parts {
			out += fmt.Sprintf("%d:%dB:%dB:%dB::primary:%s;\n", n, p[0], p[1], p[1]-p[0]+1, strings.Join(h.flags[n], ", "))
		}
		return ssh.Result{Stdout: []byte(out + "--\n")}, nil
	}
	_, args, ok := strings.Cut(cmd, "parted -s ")
	_, args, _ = strings.Cut(args, " -- ")
	if !ok {
		return ssh.Result{}, nil
	}
	args, _, _ = strings.Cut(args, "'") // the first copy of the script GuardRoot wraps
	f := strings.Fields(args)
	end := func(s string) int64 { return Partition{End: s}.wantEnd(disk) - 1 }
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "mklabel":
			h.table, i = f[i+1], i+1
		case "mkpart":
			if !h.keep {
				h.parts[len(h.parts)+1] = [2]int64{sizeBytes(f[i+2]), end(f[i+3])}
			}
			i += 3
		case "resizepart":
			n, _ := strconv.Atoi(f[i+1])
			h.parts[n] = [2]int64{h.parts[n][0], end(f[i+2])}
			i += 2
		case "set":
			n, _ := strconv.Atoi(f[i+1])
			h.flags[n] = slices.DeleteFunc(h.flags[n], func(s string) bool { return s == f[i+2] })
			if f[i+3] == "on" {
				h.flags[n] = append(h.flags[n], f[i+2])
			}
			i += 3
		}
	}
	return ssh.Result{}, nil
}

func (h *fakeParted) ranAny(s string) bool { return (&fakeDisk{ran: h.ran}).ranAny(s) }

func newParted(table string, parts map[int][2]int64) *fakeParted {
	if parts == nil {
		parts = map[int][2]int64{}
	}
	return &fakeParted{table: table, parts: parts, flags: map[int][]string{}}
}

func TestPartitionApply(t *testing.T) {
	p := Partition{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "5GiB", Label: "gpt", Flags: []string{"lvm"}}
	h := newParted("", nil)
	if err := ApplyPartition(ctx, h, p); err != nil {
		t.Fatal(err)
	}
	if !h.ranAny("parted -s -a optimal '/dev/vdb' -- mklabel gpt mkpart primary 1MiB 5GiB") || !h.ranAny("set 1 lvm on") || !h.ranAny("partprobe '/dev/vdb'") {
		t.Errorf("blank disk: ran %q", h.ran)
	}
	a, err := ReadPartition(ctx, h, p)
	if err != nil || !p.InSync(a) {
		t.Fatalf("after the apply: %+v, %v", a, err)
	}

	// Applied again, it changes nothing.
	h.ran = nil
	if err := ApplyPartition(ctx, h, p); err != nil || h.ranAny("mkpart") || h.ranAny("-- set ") {
		t.Errorf("in sync: %v, ran %q", err, h.ran)
	}

	// A flag left out of flags comes off; nil flags leave them alone.
	off := p
	off.Flags = []string{"boot"}
	if err := ApplyPartition(ctx, h, off); err != nil || !h.ranAny("set 1 boot on set 1 lvm off") {
		t.Errorf("flags: %v, ran %q", err, h.ran)
	}
	h.ran, off.Flags = nil, nil
	if err := ApplyPartition(ctx, h, off); err != nil || h.ranAny("-- set ") {
		t.Errorf("nil flags: %v, ran %q", err, h.ran)
	}

	// Growing takes resize.
	grow := p
	grow.End, grow.Flags = "100%", nil
	if err := ApplyPartition(ctx, h, grow); err == nil || !strings.Contains(err.Error(), "set resize = true to grow it") {
		t.Errorf("grow without resize: %v", err)
	}
	grow.Resize = true
	if err := ApplyPartition(ctx, h, grow); err != nil || !h.ranAny("resizepart 1 100%") {
		t.Errorf("grow: %v, ran %q", err, h.ran)
	}
}

func TestPartitionRefusals(t *testing.T) {
	p := Partition{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "5GiB", Label: "gpt"}
	at := func(start, end int64) map[int][2]int64 { return map[int][2]int64{1: {start, end}} }
	with := func(h *fakeParted, keep bool, fail string) *fakeParted {
		h.keep, h.fail = keep, fail
		return h
	}
	for name, c := range map[string]struct {
		h    *fakeParted
		p    Partition
		want string
	}{
		"another label":  {newParted("msdos", nil), p, "won't relabel a disk"},
		"out of order":   {newParted("gpt", nil), Partition{Device: "/dev/vdb", Number: 2, Start: "1MiB", End: "5GiB", Label: "gpt"}, "make the partitions in order"},
		"moved":          {newParted("gpt", at(2<<30, 5<<30-1)), p, "won't move a partition"},
		"shrunk":         {newParted("gpt", at(1<<20, 8<<30-1)), p, "won't shrink a partition"},
		"made nothing":   {with(newParted("gpt", nil), true, ""), p, "parted didn't make partition 1"},
		"parted failed":  {with(newParted("gpt", nil), false, "mkpart"), p, "exit status 1, with nothing printed"},
		"flags failed":   {with(newParted("gpt", at(1<<20, 5<<30-1)), false, "-- set "), Partition{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "5GiB", Label: "gpt", Flags: []string{"esp"}}, "exit status 1"},
		"unreadable":     {with(newParted("", nil), false, "unit B print"), p, "exit status 1"},
		"invalid number": {newParted("gpt", nil), Partition{Device: "/dev/vdb", Number: 0, Start: "1MiB", End: "5GiB", Label: "gpt"}, "number must be from 1 to 128"},
	} {
		if err := ApplyPartition(ctx, c.h, c.p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
