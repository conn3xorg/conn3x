// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// VolumeGroup is an LVM volume group on physical volumes. A device that
// isn't one yet becomes one; a device that holds anything else is left
// alone unless Force says to erase it. A physical volume in the group but
// not in PVs stays in it: taking one out moves data, which is a person's
// call.
type VolumeGroup struct {
	Name  string
	PVs   []string
	Force bool
}

// Validate checks a VolumeGroup before anything reaches the host.
func (g VolumeGroup) Validate() error {
	if err := validLVMName("name", g.Name); err != nil {
		return err
	}
	if len(g.PVs) == 0 {
		return fmt.Errorf("pvs must name at least one device")
	}
	for _, pv := range g.PVs {
		if err := validDevice("pvs", pv); err != nil {
			return err
		}
	}
	return nil
}

// VolumeGroupActual is what the host has.
type VolumeGroupActual struct {
	Exists  bool
	Missing []string // the PVs, as written, that aren't in the group
}

// ReadVolumeGroup reads the group, and which of g.PVs it's missing. A PV
// is compared by the device it resolves to, so /dev/disk/by-id/... matches
// the /dev/sdb LVM reports.
func ReadVolumeGroup(ctx context.Context, r modules.Runner, g VolumeGroup) (VolumeGroupActual, error) {
	if err := g.Validate(); err != nil {
		return VolumeGroupActual{}, err
	}
	script := needLVM + "vg=" + ssh.Quote(g.Name) + `
if vgs -- "$vg" >/dev/null 2>&1; then echo exists=1; fi
in=$(pvs --noheadings -o pv_name,vg_name 2>/dev/null | awk -v vg="$vg" '$2 == vg {print $1}' | while read -r p; do readlink -f -- "$p"; done)
for p in ` + quoteAll(g.PVs) + `; do
  r=$(readlink -f -- "$p")
  printf '%s\n' "$in" | grep -qxF -- "$r" || echo "missing=$p"
done
`
	out, err := run(ctx, r, script)
	if err != nil {
		return VolumeGroupActual{}, err
	}
	var a VolumeGroupActual
	for _, line := range strings.Split(out, "\n") {
		switch k, v, _ := strings.Cut(strings.TrimSpace(line), "="); k {
		case "exists":
			a.Exists = true
		case "missing":
			a.Missing = append(a.Missing, v)
		}
	}
	return a, nil
}

// InSync reports whether the group exists with every one of g.PVs.
func (g VolumeGroup) InSync(a VolumeGroupActual) bool { return a.Exists && len(a.Missing) == 0 }

// ApplyVolumeGroup creates the group, or extends it with the PVs it's
// missing.
func ApplyVolumeGroup(ctx context.Context, r modules.Runner, g VolumeGroup) error {
	a, err := ReadVolumeGroup(ctx, r, g)
	if err != nil {
		return err
	}
	if g.InSync(a) {
		return nil
	}
	pvs := a.Missing
	if !a.Exists {
		pvs = g.PVs
	}
	// Each new PV must hold nothing, or be a PV in no group; with force,
	// anything but a PV in another group, or a mounted file system.
	check := signature + `for p in ` + quoteAll(pvs) + `; do
  [ -b "$p" ] || { echo "$p isn't a block device on this host" >&2; exit 1; }
  owner=$(pvs --noheadings -o vg_name -- "$p" 2>/dev/null | tr -d ' ')
  [ -z "$owner" ] || { echo "$p is already in volume group $owner" >&2; exit 1; }
  t=$(sig "$p")
  m=$(findmnt -n -o TARGET -S "$p" 2>/dev/null | head -n 1)
  [ -z "$m" ] || { echo "$p is mounted at $m" >&2; exit 1; }
`
	if !g.Force {
		check += `  case $t in ''|LVM2_member) ;; *) echo "$p already holds a $t file system. Adding it to a volume group erases it, so Conn3x won't unless you set force = true" >&2; exit 1 ;; esac
`
	}
	check += "done\n"
	yes := ""
	if g.Force {
		yes = "-y "
	}
	vg := ssh.Quote(g.Name)
	if a.Exists {
		check += "vgextend " + yes + "-- " + vg + " " + quoteAll(pvs)
	} else {
		check += "vgcreate " + yes + "-- " + vg + " " + quoteAll(pvs)
	}
	if _, err := run(ctx, r, needLVM+check); err != nil {
		return fmt.Errorf("volume group %s: %w", g.Name, err)
	}
	after, err := ReadVolumeGroup(ctx, r, g)
	if err != nil {
		return err
	}
	if !g.InSync(after) {
		return fmt.Errorf("volume group %s still lacks %s after the change", g.Name, strings.Join(after.Missing, ", "))
	}
	return nil
}

// LogicalVolume is an LVM logical volume in a volume group. It grows to its
// size, and shrinks only with Force, since that destroys whatever is past
// the new end.
type LogicalVolume struct {
	VG, Name, Size string
	Force          bool
}

var (
	absSize = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([bBkKmMgGtTpP]?)$`)
	pctSize = regexp.MustCompile(`^([0-9]+)%(VG|FREE)$`)
)

// Validate checks a LogicalVolume before anything reaches the host.
func (l LogicalVolume) Validate() error {
	if err := validLVMName("vg", l.VG); err != nil {
		return err
	}
	if err := validLVMName("name", l.Name); err != nil {
		return err
	}
	if m := pctSize.FindStringSubmatch(l.Size); m != nil {
		if n, _ := strconv.Atoi(m[1]); n < 1 || n > 100 {
			return fmt.Errorf("size %q must be from 1%% to 100%%", l.Size)
		}
		return nil
	}
	if n, err := l.bytes(); err != nil || n <= 0 {
		return fmt.Errorf("size %q must be a size such as 512m, 20g or 1.5t, or a share such as 50%%VG or 100%%FREE", l.Size)
	}
	return nil
}

// bytes is an absolute size in bytes, in LVM's binary units; a bare number
// is MiB, as for lvcreate -L.
func (l LogicalVolume) bytes() (int64, error) {
	m := absSize.FindStringSubmatch(l.Size)
	if m == nil {
		return 0, fmt.Errorf("not a size")
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, err
	}
	shift := map[string]int{"b": 0, "k": 10, "": 20, "m": 20, "g": 30, "t": 40, "p": 50}[strings.ToLower(m[2])]
	v := n * math.Pow(2, float64(shift))
	if v > math.MaxInt64/2 {
		return 0, fmt.Errorf("too big")
	}
	return int64(v), nil
}

// LogicalVolumeActual is what the host has.
type LogicalVolumeActual struct {
	Exists                   bool
	Size, ExtentSize, VGSize int64
}

// ReadLogicalVolume reads the volume, and its group's sizes.
func ReadLogicalVolume(ctx context.Context, r modules.Runner, l LogicalVolume) (LogicalVolumeActual, error) {
	if err := l.Validate(); err != nil {
		return LogicalVolumeActual{}, err
	}
	script := needLVM + "vg=" + ssh.Quote(l.VG) + " lv=" + ssh.Quote(l.VG+"/"+l.Name) + `
vgs -- "$vg" >/dev/null 2>&1 || { echo "volume group $vg doesn't exist on this host; a lvm_volume_group step before this one makes it" >&2; exit 1; }
vgs --noheadings --units b --nosuffix -o vg_extent_size,vg_size -- "$vg" | awk '{print "extent=" $1; print "vgsize=" $2}'
if lvs -- "$lv" >/dev/null 2>&1; then
  echo exists=1
  lvs --noheadings --units b --nosuffix -o lv_size -- "$lv" | awk '{print "size=" $1}'
fi
`
	out, err := run(ctx, r, script)
	if err != nil {
		return LogicalVolumeActual{}, err
	}
	v := fields(out)
	return LogicalVolumeActual{Exists: v["exists"] == "1", Size: number(v["size"]), ExtentSize: number(v["extent"]), VGSize: number(v["vgsize"])}, nil
}

// Target is the size the volume should be, in bytes, rounded up to whole
// extents as LVM does; 0 for a share of FREE, which only sizes it when it's
// made, since the free space shrinks once it is.
func (l LogicalVolume) Target(a LogicalVolumeActual) int64 {
	ext := a.ExtentSize
	if ext <= 0 {
		ext = 1
	}
	if m := pctSize.FindStringSubmatch(l.Size); m != nil {
		if m[2] == "FREE" {
			return 0
		}
		pct, _ := strconv.ParseInt(m[1], 10, 64)
		return a.VGSize / ext * pct / 100 * ext
	}
	n, _ := l.bytes()
	return (n + ext - 1) / ext * ext
}

// InSync reports whether the volume exists at its size.
func (l LogicalVolume) InSync(a LogicalVolumeActual) bool {
	t := l.Target(a)
	return a.Exists && (t == 0 || a.Size == t)
}

// sizeFlag is lvcreate's and lvextend's size argument.
func (l LogicalVolume) sizeFlag() string {
	if pctSize.MatchString(l.Size) {
		return "-l " + ssh.Quote(l.Size)
	}
	return "-L " + ssh.Quote(l.Size)
}

// ApplyLogicalVolume creates the volume, or grows it, or with Force
// shrinks it.
func ApplyLogicalVolume(ctx context.Context, r modules.Runner, l LogicalVolume) error {
	a, err := ReadLogicalVolume(ctx, r, l)
	if err != nil {
		return err
	}
	if l.InSync(a) {
		return nil
	}
	lv := ssh.Quote(l.VG + "/" + l.Name)
	var script string
	switch t := l.Target(a); {
	case !a.Exists:
		// The space is new to this volume: an old signature in it is stale.
		script = "lvcreate -y -W y -n " + ssh.Quote(l.Name) + " " + l.sizeFlag() + " -- " + ssh.Quote(l.VG)
	case a.Size < t:
		script = "lvextend " + l.sizeFlag() + " -- " + lv
	case !l.Force:
		return fmt.Errorf("%s/%s is %s, bigger than its size %s. Shrinking it destroys whatever is past the new end, file system included, so Conn3x won't unless you set force = true", l.VG, l.Name, bytes(a.Size), l.Size)
	default:
		script = "lvreduce -f " + l.sizeFlag() + " -- " + lv
	}
	if _, err := run(ctx, r, script); err != nil {
		return fmt.Errorf("logical volume %s/%s: %w", l.VG, l.Name, err)
	}
	after, err := ReadLogicalVolume(ctx, r, l)
	if err != nil {
		return err
	}
	if !l.InSync(after) {
		return fmt.Errorf("%s/%s is %s after the change, not %s", l.VG, l.Name, bytes(after.Size), bytes(l.Target(after)))
	}
	return nil
}
