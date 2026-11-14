// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Partition is one partition on a disk, made with parted. It never shrinks,
// moves or deletes one with data on it; growing it takes Resize.
type Partition struct {
	Device string   // the disk, such as /dev/vdb
	Number int      // 1 to 128
	Start  string   // such as 1MiB or 10GiB
	End    string   // such as 10GiB, or 100% for the rest of the disk
	Label  string   // the disk's partition table: gpt (default) or msdos
	Flags  []string // the partition's whole set of flags; nil leaves them alone
	Resize bool     // grow the partition when End moves out
}

var (
	partSize  = regexp.MustCompile(`^([0-9]+)(MiB|GiB|TiB)$`)
	partEnd   = regexp.MustCompile(`^([0-9]{1,3})%$`)
	partFlags = []string{"boot", "esp", "lvm", "raid", "swap", "hidden", "bios_grub", "legacy_boot", "msftdata", "msftres", "diag", "prep"}
)

const mib = 1 << 20

// Validate checks a partition before anything reaches the host.
func (p Partition) Validate() error {
	if err := validDevice("device", p.Device); err != nil {
		return err
	}
	if p.Number < 1 || p.Number > 128 {
		return fmt.Errorf("number must be from 1 to 128, not %d", p.Number)
	}
	if !partSize.MatchString(p.Start) {
		return fmt.Errorf(`start %q must be a size in MiB, GiB or TiB, such as "1MiB"`, p.Start)
	}
	if !partSize.MatchString(p.End) && !partEnd.MatchString(p.End) {
		return fmt.Errorf(`end %q must be a size in MiB, GiB or TiB, or a percentage of the disk, such as "100%%"`, p.End)
	}
	if m := partEnd.FindStringSubmatch(p.End); m != nil {
		if n, _ := strconv.Atoi(m[1]); n < 1 || n > 100 {
			return fmt.Errorf("end %q must be from 1%% to 100%%", p.End)
		}
	}
	if p.Label != "gpt" && p.Label != "msdos" {
		return fmt.Errorf(`label must be "gpt" or "msdos", not %q`, p.Label)
	}
	if p.Label == "msdos" && p.Number > 4 {
		return errors.New("an msdos disk has four primary partitions; use a gpt label for more")
	}
	for _, f := range p.Flags {
		if !slices.Contains(partFlags, f) {
			return fmt.Errorf("flag %q isn't one parted sets, such as %s", f, strings.Join(partFlags, ", "))
		}
	}
	return nil
}

func sizeBytes(s string) int64 {
	m := partSize.FindStringSubmatch(s)
	n, _ := strconv.ParseInt(m[1], 10, 64)
	switch m[2] {
	case "GiB":
		return n << 30
	case "TiB":
		return n << 40
	}
	return n << 20
}

// PartitionActual is what parted prints for the disk and the partition.
type PartitionActual struct {
	DiskBytes  int64
	Table      string // gpt, msdos, or "" with no partition table
	Exists     bool
	Start, End int64 // bytes, End inclusive as parted prints it
	Flags      []string
	Signature  string // what blkid finds on the partition: a filesystem, LVM, ...
	Numbers    []int  // every partition on the disk
}

// nextFree is the number parted gives the next partition it makes: the
// lowest one not taken.
func (a PartitionActual) nextFree() int {
	for n := 1; ; n++ {
		if !slices.Contains(a.Numbers, n) {
			return n
		}
	}
}

// wantEnd is where End falls on a disk of size bytes.
func (p Partition) wantEnd(disk int64) int64 {
	if m := partEnd.FindStringSubmatch(p.End); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return disk * n / 100
	}
	return sizeBytes(p.End)
}

// near reports whether two offsets agree within a MiB, as parted's
// alignment and the backup GPT at the disk's end leave them.
func near(a, b int64) bool { return a-b < 2*mib && b-a < 2*mib }

// InSync reports whether the partition is there as wanted.
func (p Partition) InSync(a PartitionActual) bool {
	if !a.Exists || a.Table != p.Label || !near(a.Start, sizeBytes(p.Start)) || !near(a.End+1, p.wantEnd(a.DiskBytes)) {
		return false
	}
	if p.Flags != nil {
		want, got := slices.Clone(p.Flags), slices.Clone(a.Flags)
		slices.Sort(want)
		slices.Sort(got)
		return slices.Equal(want, got)
	}
	return true
}

// ReadPartition reads the disk's table and the partition with parted.
func ReadPartition(ctx context.Context, r modules.Runner, p Partition) (PartitionActual, error) {
	if err := p.Validate(); err != nil {
		return PartitionActual{}, err
	}
	out, err := run(ctx, r, fmt.Sprintf(`command -v parted >/dev/null || { echo "parted isn't installed; add a package step for parted first" >&2; exit 1; }
d=%s
[ -b "$d" ] || { echo "$d isn't a block device on this host" >&2; exit 1; }
LC_ALL=C parted -m -s "$d" unit B print 2>/dev/null || true
echo '--'
part=$(lsblk -lnpo NAME,PARTN "$d" 2>/dev/null | awk -v n=%d '$2==n{print $1}')
[ -n "$part" ] && blkid -p -o value -s TYPE "$part" 2>/dev/null; true`, ssh.Quote(p.Device), p.Number))
	if err != nil {
		return PartitionActual{}, err
	}
	return parsePartition(out, p.Number)
}

// parsePartition reads parted -m's machine form:
//
//	BYT;
//	/dev/vdb:10737418240B:virtblk:512:512:gpt:Virtio Block Device:;
//	1:1048576B:5368709119B:5367660544B:xfs:data:lvm;
func parsePartition(out string, number int) (PartitionActual, error) {
	parted, sig, _ := strings.Cut(out, "--\n")
	var a PartitionActual
	a.Signature = strings.TrimSpace(sig)
	for _, line := range strings.Split(parted, "\n") {
		line = strings.TrimSuffix(strings.TrimSpace(line), ";")
		f := strings.Split(line, ":")
		switch {
		case len(f) >= 6 && strings.HasPrefix(f[0], "/dev/"):
			a.DiskBytes, _ = strconv.ParseInt(strings.TrimSuffix(f[1], "B"), 10, 64)
			if f[5] != "unknown" && f[5] != "loop" {
				a.Table = f[5]
			}
		case len(f) >= 7 && f[0] != "" && f[0][0] >= '0' && f[0][0] <= '9':
			n, _ := strconv.Atoi(f[0])
			a.Numbers = append(a.Numbers, n)
			if n != number {
				continue
			}
			a.Exists = true
			a.Start, _ = strconv.ParseInt(strings.TrimSuffix(f[1], "B"), 10, 64)
			a.End, _ = strconv.ParseInt(strings.TrimSuffix(f[2], "B"), 10, 64)
			for _, fl := range strings.Split(f[6], ",") {
				if fl = strings.TrimSpace(fl); fl != "" {
					a.Flags = append(a.Flags, fl)
				}
			}
		}
	}
	if a.DiskBytes == 0 {
		return a, errors.New("parted printed no disk size")
	}
	return a, nil
}

// ApplyPartition makes the label on a blank disk, makes the partition, grows
// it when Resize says so, and sets its flags. It refuses to shrink or move a
// partition, or to relabel a disk that has a table.
func ApplyPartition(ctx context.Context, r modules.Runner, p Partition) error {
	a, err := ReadPartition(ctx, r, p)
	if err != nil {
		return err
	}
	var cmds []string
	switch {
	case a.Table == "":
		cmds = append(cmds, "mklabel "+p.Label)
	case a.Table != p.Label:
		return fmt.Errorf("%s has a %s partition table, not %s; Conn3x won't relabel a disk, which would lose every partition on it", p.Device, a.Table, p.Label)
	}
	want := p.wantEnd(a.DiskBytes)
	switch {
	case !a.Exists && a.nextFree() != p.Number:
		return fmt.Errorf("parted would number a new partition on %s %d, not %d: make the partitions in order", p.Device, a.nextFree(), p.Number)
	case !a.Exists:
		// "primary" is the type on msdos and the name on gpt: either way
		// parted then reads the start and end as such.
		cmds = append(cmds, "mkpart primary "+p.Start+" "+p.End)
	case !near(a.Start, sizeBytes(p.Start)):
		return fmt.Errorf("partition %d on %s starts at %dMiB, not %s; Conn3x won't move a partition", p.Number, p.Device, a.Start/mib, p.Start)
	case a.End+1 < want-2*mib && p.Resize:
		cmds = append(cmds, fmt.Sprintf("resizepart %d %s", p.Number, p.End))
	case a.End+1 < want-2*mib:
		return fmt.Errorf("partition %d on %s ends at %dMiB, short of %s; set resize = true to grow it", p.Number, p.Device, (a.End+1)/mib, p.End)
	case a.End+1 > want+2*mib:
		return fmt.Errorf("partition %d on %s ends at %dMiB, past %s; Conn3x won't shrink a partition, which can lose what's on it", p.Number, p.Device, (a.End+1)/mib, p.End)
	}
	if len(cmds) > 0 {
		if _, err := run(ctx, r, fmt.Sprintf("LC_ALL=C parted -s -a optimal %s -- %s", ssh.Quote(p.Device), strings.Join(cmds, " "))); err != nil {
			return err
		}
		if a, err = ReadPartition(ctx, r, p); err != nil {
			return err
		}
		if !a.Exists {
			return fmt.Errorf("parted didn't make partition %d on %s", p.Number, p.Device)
		}
	}
	if p.Flags != nil {
		var set []string
		for _, f := range partFlags {
			on, had := slices.Contains(p.Flags, f), slices.Contains(a.Flags, f)
			if on != had {
				set = append(set, fmt.Sprintf("set %d %s %s", p.Number, f, map[bool]string{true: "on", false: "off"}[on]))
			}
		}
		if len(set) > 0 {
			if _, err := run(ctx, r, fmt.Sprintf("LC_ALL=C parted -s %s -- %s", ssh.Quote(p.Device), strings.Join(set, " "))); err != nil {
				return err
			}
		}
	}
	_, err = run(ctx, r, "udevadm settle 2>/dev/null; partprobe "+ssh.Quote(p.Device)+" 2>/dev/null; true")
	return err
}
