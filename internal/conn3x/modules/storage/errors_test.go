// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// failAt passes commands to r until the nth (from 0), which fails with
// errLost as a dropped connection does.
type failAt struct {
	r modules.Runner
	n int
}

var errLost = errors.New("connection lost")

func (f *failAt) Run(ctx context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	if f.n == 0 {
		return ssh.Result{}, errLost
	}
	f.n--
	return f.r.Run(ctx, cmd, stdin)
}

// Whichever command the connection drops on, the error comes back and
// nothing claims success.
func TestHostErrorsPassOn(t *testing.T) {
	for name, c := range map[string]struct {
		host  func() modules.Runner
		apply func(modules.Runner) error
		runs  int
	}{
		"filesystem made": {
			func() modules.Runner { return &fakeDisk{devSize: 10 << 30} },
			func(r modules.Runner) error {
				return ApplyFilesystem(ctx, r, Filesystem{Device: "/dev/sdb", Type: "ext4"})
			}, 3,
		},
		"filesystem grown": {
			func() modules.Runner { return &fakeDisk{fsType: "ext4", devSize: 20 << 30, fsSize: 10 << 30} },
			func(r modules.Runner) error {
				return ApplyFilesystem(ctx, r, Filesystem{Device: "/dev/sdb", Type: "ext4", Resize: true})
			}, 3,
		},
		"volume created": {
			func() modules.Runner { return &fakeDisk{extent: 4 << 20, vgSize: 10 << 30} },
			func(r modules.Runner) error {
				return ApplyLogicalVolume(ctx, r, LogicalVolume{VG: "vg0", Name: "data", Size: "2g"})
			}, 3,
		},
		"group created": {
			func() modules.Runner { return &recorder{} },
			func(r modules.Runner) error {
				return ApplyVolumeGroup(ctx, r, VolumeGroup{Name: "vg0", PVs: []string{"/dev/sdb"}})
			}, 3,
		},
		"partition made": {
			func() modules.Runner { return newParted("", nil) },
			func(r modules.Runner) error {
				return ApplyPartition(ctx, r, Partition{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "5GiB", Label: "gpt"})
			}, 4,
		},
	} {
		for n := range c.runs {
			if err := c.apply(&failAt{c.host(), n}); !errors.Is(err, errLost) {
				t.Errorf("%s, failing run %d: err = %v", name, n, err)
			}
		}
	}
}

func TestFilesystemReadBack(t *testing.T) {
	// The host takes the mkfs but the device reads back empty.
	h := &recorder{}
	err := ApplyFilesystem(ctx, h, Filesystem{Device: "/dev/sdb", Type: "xfs"})
	if err == nil || err.Error() != `/dev/sdb holds "" of 0 bytes after the change, not a xfs file system filling the device` {
		t.Errorf("got %v", err)
	}
	// Grown, in sync without resize: nothing beyond the reads runs.
	d := &fakeDisk{fsType: "ext4", devSize: 20 << 30, fsSize: 10 << 30}
	if err := ApplyFilesystem(ctx, d, Filesystem{Device: "/dev/sdb", Type: "ext4"}); err != nil || len(d.ran) != 2 {
		t.Errorf("in sync: %v, ran %q", err, d.ran)
	}
	if err := ApplyFilesystem(ctx, d, Filesystem{Device: "sdb", Type: "ext4"}); err == nil || len(d.ran) != 2 {
		t.Errorf("an invalid device reached the host: %v", err)
	}
	if _, err := ReadFilesystem(ctx, d, Filesystem{Device: "/dev/../etc/x"}); err == nil || !strings.Contains(err.Error(), "must be a device path under /dev") {
		t.Errorf("read: %v", err)
	}
}

func TestVolumeGroupApply(t *testing.T) {
	g := VolumeGroup{Name: "vg0", PVs: []string{"/dev/sdb", "/dev/sdc"}}
	answer := func(outs ...string) *answers { return &answers{outs: outs} }

	// In sync: nothing written.
	h := answer("exists=1\n")
	if err := ApplyVolumeGroup(ctx, h, g); err != nil || len(h.ran) != 1 {
		t.Errorf("in sync: %v, ran %d", err, len(h.ran))
	}
	// An existing group is extended with only what it lacks.
	h = answer("exists=1\nmissing=/dev/sdc\n", "", "exists=1\n")
	if err := ApplyVolumeGroup(ctx, h, g); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.ran[1], "vgextend -- 'vg0' '/dev/sdc'") || strings.Contains(h.ran[1], "'/dev/sdb'") {
		t.Errorf("extend: %s", h.ran[1])
	}
	h = answer("exists=1\nmissing=/dev/sdc\n", "", "exists=1\nmissing=/dev/sdc\n")
	if err := ApplyVolumeGroup(ctx, h, g); err == nil || err.Error() != "volume group vg0 still lacks /dev/sdc after the change" {
		t.Errorf("still missing: %v", err)
	}
	h = &answers{outs: []string{"missing=/dev/sdb\n"}, fail: 2}
	if err := ApplyVolumeGroup(ctx, h, g); err == nil || err.Error() != "volume group vg0: /dev/sdb is mounted at /srv" {
		t.Errorf("refused: %v", err)
	}
	for _, bad := range []VolumeGroup{{Name: "vg0"}, {Name: "-x", PVs: []string{"/dev/sdb"}}, {Name: "vg0", PVs: []string{"sdb"}}} {
		if err := ApplyVolumeGroup(ctx, &recorder{}, bad); err == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}

// answers prints each of outs in turn, and fails command number fail, counting
// from 1, with an error from the host.
type answers struct {
	outs []string
	fail int
	ran  []string
}

func (h *answers) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, unwrap(cmd))
	if len(h.ran) == h.fail {
		return ssh.Result{ExitCode: 1, Stderr: []byte("/dev/sdb is mounted at /srv\n")}, nil
	}
	var out string
	if len(h.outs) > 0 {
		out, h.outs = h.outs[0], h.outs[1:]
	}
	return ssh.Result{Stdout: []byte(out)}, nil
}

func TestLogicalVolumeChanges(t *testing.T) {
	l := LogicalVolume{VG: "vg0", Name: "data", Size: "50%VG"}
	read := "extent=4194304\nvgsize=10737418240\nexists=1\nsize=%d\n"
	// In sync, a share of the group.
	h := &answers{outs: []string{strings.Replace(read, "%d", "5368709120", 1)}}
	if err := ApplyLogicalVolume(ctx, h, l); err != nil || len(h.ran) != 1 {
		t.Errorf("in sync: %v, ran %q", err, h.ran)
	}
	// Grown by share, and checked after.
	h = &answers{outs: []string{strings.Replace(read, "%d", "1073741824", 1), "", strings.Replace(read, "%d", "1073741824", 1)}}
	err := ApplyLogicalVolume(ctx, h, l)
	if !strings.Contains(h.ran[1], "lvextend -l '50%VG' -- 'vg0/data'") {
		t.Errorf("grow: %s", h.ran[1])
	}
	if err == nil || err.Error() != "vg0/data is 1 GiB after the change, not 5 GiB" {
		t.Errorf("didn't grow: %v", err)
	}
	// Shrunk with force.
	l = LogicalVolume{VG: "vg0", Name: "data", Size: "1g", Force: true}
	h = &answers{outs: []string{strings.Replace(read, "%d", "2147483648", 1), "", strings.Replace(read, "%d", "1073741824", 1)}}
	if err := ApplyLogicalVolume(ctx, h, l); err != nil || !strings.Contains(h.ran[1], "lvreduce -f -L '1g' -- 'vg0/data'") {
		t.Errorf("shrink: %v, ran %q", err, h.ran)
	}
	h = &answers{outs: []string{strings.Replace(read, "%d", "2147483648", 1)}, fail: 2}
	if err := ApplyLogicalVolume(ctx, h, l); err == nil || !strings.HasPrefix(err.Error(), "logical volume vg0/data: ") {
		t.Errorf("lvreduce fails: %v", err)
	}
	// A share of FREE sizes the volume only when it's made.
	free := LogicalVolume{VG: "vg0", Name: "data", Size: "100%FREE"}
	if !free.InSync(LogicalVolumeActual{Exists: true, Size: 1}) || free.InSync(LogicalVolumeActual{}) {
		t.Error("a share of FREE sizes only a new volume")
	}
	if got := (LogicalVolume{Size: "1g"}).Target(LogicalVolumeActual{}); got != 1<<30 {
		t.Errorf("target with no extent size: %d", got)
	}
}

func TestSizesAndNames(t *testing.T) {
	for _, bad := range []LogicalVolume{
		{VG: "vg0", Name: "data", Size: "0%VG"},
		{VG: "vg0", Name: "data", Size: "99999999999999999999p"},
		{VG: "vg0", Name: "..", Size: "1g"},
		{VG: "vg0", Name: "data", Size: "0"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	if err := (LogicalVolume{VG: "vg0", Name: "data", Size: "1.5t"}).Validate(); err != nil {
		t.Error(err)
	}
	for _, bad := range []Partition{
		{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "5GB", Label: "gpt"},
		{Device: "/dev/vdb", Number: 1, Start: "1MiB", End: "5GiB", Label: "dos"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	if sizeBytes("2TiB") != 2<<40 || sizeBytes("3GiB") != 3<<30 || sizeBytes("5MiB") != 5<<20 {
		t.Error("sizeBytes")
	}
	if _, err := parsePartition("BYT;\n--\n", 1); err == nil || err.Error() != "parted printed no disk size" {
		t.Errorf("no disk: %v", err)
	}
	if _, err := run(ctx, &answers{fail: 0}, "x"); err != nil {
		t.Error(err)
	}
	h := &answers{fail: 1}
	if _, err := run(ctx, h, "x"); err == nil || err.Error() != "/dev/sdb is mounted at /srv" {
		t.Errorf("stderr: %v", err)
	}
}
