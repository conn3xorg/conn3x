// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Filesystem is a file system on a block device, made if the device has
// none, and grown to fill it with Resize.
type Filesystem struct {
	Device, Type string
	Opts         []string // extra mkfs options, used only when making it
	Resize       bool
	Force        bool // make it over a different file system, erasing it
}

// mkfs is how each type is made, and the flag that makes it over another.
var mkfs = map[string]struct{ cmd, force string }{
	"ext2":  {"mkfs.ext2 -q", "-F"},
	"ext3":  {"mkfs.ext3 -q", "-F"},
	"ext4":  {"mkfs.ext4 -q", "-F"},
	"xfs":   {"mkfs.xfs -q", "-f"},
	"btrfs": {"mkfs.btrfs -q", "-f"},
	"vfat":  {"mkfs.vfat", "-I"},
	"swap":  {"mkswap", "-f"},
}

// FilesystemTypes lists the types a filesystem step can make.
func FilesystemTypes() []string {
	out := make([]string, 0, len(mkfs))
	for t := range mkfs {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// growable are the types Resize can grow.
var growable = []string{"ext2", "ext3", "ext4", "xfs"}

// Validate checks a Filesystem before anything reaches the host.
func (f Filesystem) Validate() error {
	if err := validDevice("device", f.Device); err != nil {
		return err
	}
	if _, ok := mkfs[f.Type]; !ok {
		return fmt.Errorf("type %q isn't one Conn3x makes; use one of %s", f.Type, strings.Join(FilesystemTypes(), ", "))
	}
	if f.Resize && !slices.Contains(growable, f.Type) {
		return fmt.Errorf("resize grows %s file systems, not %s", strings.Join(growable, ", "), f.Type)
	}
	for _, o := range f.Opts {
		if !mkfsOpt.MatchString(o) {
			return fmt.Errorf("opts %q must be one mkfs option or value, without spaces or shell characters", o)
		}
	}
	return nil
}

// FilesystemActual is what a device holds.
type FilesystemActual struct {
	Type       string // "" when it holds nothing
	DeviceSize int64
	Size       int64  // the file system's size, read only for Resize
	MountedAt  string // "" when it isn't mounted
}

// growSlack is how much bigger than its file system a device may be
// before Resize grows it. shortcut: XFS can leave the end of a device
// unused after growing, less than one allocation group; 32 MiB keeps that
// from showing as drift. Measure per type if it's ever too coarse.
const growSlack = 32 << 20

// InSync reports whether the device holds the file system, grown to fill it
// with Resize.
func (f Filesystem) InSync(a FilesystemActual) bool {
	return a.Type == f.Type && (!f.Resize || a.DeviceSize-a.Size < growSlack)
}

// ReadFilesystem reads what f.Device holds.
func ReadFilesystem(ctx context.Context, r modules.Runner, f Filesystem) (FilesystemActual, error) {
	if err := validDevice("device", f.Device); err != nil {
		return FilesystemActual{}, err
	}
	script := signature + "d=" + ssh.Quote(f.Device) + `
[ -b "$d" ] || { echo "$d isn't a block device on this host" >&2; exit 1; }
t=$(sig "$d")
echo "type=$t"
echo "devsize=$(blockdev --getsize64 "$d")"
echo "mounted=$(findmnt -n -o TARGET -S "$d" 2>/dev/null | head -n 1)"
`
	if f.Resize {
		script += `case $t in
ext2|ext3|ext4) echo "size=$(dumpe2fs -h "$d" 2>/dev/null | awk -F: '/^Block count/{c=$2} /^Block size/{s=$2} END{printf "%.0f", c*s}')" ;;
xfs) echo "size=$(xfs_db -r -c 'sb 0' -c 'p dblocks' -c 'p blocksize' "$d" 2>/dev/null | awk '/^dblocks/{c=$3} /^blocksize/{s=$3} END{printf "%.0f", c*s}')" ;;
esac
`
	}
	out, err := run(ctx, r, script)
	if err != nil {
		return FilesystemActual{}, err
	}
	v := fields(out)
	return FilesystemActual{Type: v["type"], DeviceSize: number(v["devsize"]), Size: number(v["size"]), MountedAt: v["mounted"]}, nil
}

// ApplyFilesystem makes the file system if the device holds none, refuses
// to make it over anything else without Force, and grows it with Resize.
func ApplyFilesystem(ctx context.Context, r modules.Runner, f Filesystem) error {
	if err := f.Validate(); err != nil {
		return err
	}
	a, err := ReadFilesystem(ctx, r, f)
	if err != nil {
		return err
	}
	if a.Type != f.Type {
		if err := f.make(ctx, r, a); err != nil {
			return err
		}
	} else if f.Resize && !f.InSync(a) {
		if err := f.grow(ctx, r, a); err != nil {
			return err
		}
	}
	got, err := ReadFilesystem(ctx, r, f)
	if err != nil {
		return err
	}
	if !f.InSync(got) {
		return fmt.Errorf("%s holds %q of %s after the change, not a %s file system filling the device", f.Device, got.Type, bytes(got.Size), f.Type)
	}
	return nil
}

func (f Filesystem) make(ctx context.Context, r modules.Runner, a FilesystemActual) error {
	m := mkfs[f.Type]
	cmd := m.cmd
	if a.Type != "" {
		what := "a " + a.Type + " file system"
		if a.Type == "LVM2_member" {
			what = "an LVM physical volume"
		}
		switch {
		case a.MountedAt != "":
			return fmt.Errorf("%s holds %s, mounted at %s. Conn3x won't make a %s file system over it; unmount it first, and set force = true if erasing it is what you want", f.Device, what, a.MountedAt, f.Type)
		case !f.Force:
			return fmt.Errorf("%s already holds %s. Making a %s file system there erases everything on it, so Conn3x won't unless you set force = true", f.Device, what, f.Type)
		}
		cmd += " " + m.force
	}
	if len(f.Opts) > 0 {
		cmd += " " + quoteAll(f.Opts)
	}
	_, err := run(ctx, r, cmd+" "+ssh.Quote(f.Device))
	if err != nil {
		return fmt.Errorf("making a %s file system on %s: %w", f.Type, f.Device, err)
	}
	return nil
}

func (f Filesystem) grow(ctx context.Context, r modules.Runner, a FilesystemActual) error {
	d := ssh.Quote(f.Device)
	var script string
	switch {
	case f.Type == "xfs" && a.MountedAt == "":
		return fmt.Errorf("%s has room for its xfs file system to grow by %s, but xfs grows only while mounted; mount it, with a mount step, and apply again", f.Device, bytes(a.DeviceSize-a.Size))
	case f.Type == "xfs":
		script = "xfs_growfs " + ssh.Quote(a.MountedAt)
	case a.MountedAt == "":
		// resize2fs refuses an unmounted file system that wasn't just checked.
		script = "e2fsck -f -p " + d + " && resize2fs " + d
	default:
		script = "resize2fs " + d
	}
	if _, err := run(ctx, r, script); err != nil {
		return fmt.Errorf("growing the file system on %s: %w", f.Device, err)
	}
	return nil
}
