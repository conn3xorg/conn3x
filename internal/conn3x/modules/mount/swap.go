// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mount

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Swap is a swap file or device, in /etc/fstab and on.
type Swap struct {
	Path string
	// Size, such as "2G" or "512M", makes Path a swap file of that size.
	// Empty means Path is a device or file that's already swap.
	Size     string
	Priority string // -1 to 32767, or "" for the kernel's choice
}

var swapSize = regexp.MustCompile(`^([1-9][0-9]{0,6})([MG])$`)

// Validate checks a Swap before anything reaches the host.
func (s Swap) Validate() error {
	if !path.IsAbs(s.Path) || path.Clean(s.Path) != s.Path || s.Path == "/" || !fstabWord.MatchString(s.Path) {
		return fmt.Errorf("path %q must be a clean absolute path without spaces", s.Path)
	}
	if s.Size != "" && !swapSize.MatchString(s.Size) {
		return fmt.Errorf("size %q must be a whole number of megabytes or gigabytes, such as \"512M\" or \"2G\"", s.Size)
	}
	if s.Size != "" && strings.HasPrefix(s.Path, "/dev/") {
		return fmt.Errorf("size is for a swap file; %s is a device, so leave size unset", s.Path)
	}
	if s.Priority != "" {
		if n, err := strconv.Atoi(s.Priority); err != nil || n < -1 || n > 32767 {
			return fmt.Errorf("priority %q must be a number from -1 to 32767", s.Priority)
		}
	}
	return nil
}

// Bytes is Size in bytes, 0 when unset.
func (s Swap) Bytes() int64 {
	m := swapSize.FindStringSubmatch(s.Size)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	if m[2] == "G" {
		return n << 30
	}
	return n << 20
}

// Line is the entry Conn3x writes to /etc/fstab.
func (s Swap) Line() string {
	opts := "defaults"
	if s.Priority != "" {
		opts = "pri=" + s.Priority
	}
	return fmt.Sprintf("%s none swap %s 0 0", s.Path, opts)
}

func (s Swap) entryRegexp() string {
	return `^\s*` + regexp.QuoteMeta(s.Path) + `\s+\S+\s+swap\s`
}

// swapLine returns the swap entry for src, with its fields single-spaced.
func swapLine(content, src string) string {
	for _, line := range strings.Split(content, "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == src && f[2] == "swap" {
			return strings.Join(f, " ")
		}
	}
	return ""
}

// SwapActual is what the host has for a swap path.
type SwapActual struct {
	Entry    string // the fstab entry, or ""
	On       bool
	Priority string // the live priority, when on
	Bytes    int64  // the file's size, -1 when it isn't a regular file
}

// InSync reports whether the entry is as wanted, the swap is on with the
// priority asked for, and a swap file has its size.
func (s Swap) InSync(a SwapActual) bool {
	return a.Entry == s.Line() && a.On && (s.Priority == "" || a.Priority == s.Priority) && (s.Size == "" || a.Bytes == s.Bytes())
}

// swapState prints "on PRIORITY" or "off", then the size or -1. /proc/swaps
// lists the resolved path, so a link such as /dev/disk/by-uuid/... is
// resolved first.
const swapState = `real=$(readlink -f -- "$p" || printf '%s' "$p")
awk -v f="$real" '$1==f{print "on", $5; found=1} END{if(!found) print "off"}' /proc/swaps
if [ -f "$p" ] && [ ! -L "$p" ]; then stat -c %s -- "$p"; else echo -1; fi
`

// ReadSwap returns the fstab entry, whether the swap is on, and its size.
func ReadSwap(ctx context.Context, r modules.Runner, s Swap) (SwapActual, error) {
	f, err := file.Read(ctx, r, fstab)
	if err != nil {
		return SwapActual{}, err
	}
	a := SwapActual{Entry: swapLine(f.Content, s.Path)}
	res, err := r.Run(ctx, "p="+ssh.Quote(s.Path)+"\n"+swapState, nil)
	if err := check(res, err); err != nil {
		return a, err
	}
	return parseSwapState(a, string(res.Stdout))
}

func parseSwapState(a SwapActual, out string) (SwapActual, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		return a, fmt.Errorf("unexpected swap state %q", out)
	}
	if f := strings.Fields(lines[0]); len(f) == 2 && f[0] == "on" {
		a.On, a.Priority = true, f[1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil {
		return a, fmt.Errorf("unexpected swap file size %q", lines[1])
	}
	a.Bytes = n
	return a, nil
}

// ApplySwap makes the swap file when Size is set, remaking it when the
// size changed, then turns it on and writes its fstab entry. A device or
// file that isn't swap yet is refused rather than formatted, since mkswap
// wipes what's there.
func ApplySwap(ctx context.Context, r modules.Runner, s Swap) error {
	if err := s.Validate(); err != nil {
		return err
	}
	script := "set -e\np=" + ssh.Quote(s.Path) + "\n" + `on() { awk -v f="$(readlink -f -- "$p")" '$1==f{found=1} END{exit !found}' /proc/swaps; }
dir=$(dirname -- "$p")
if [ -k "$dir" ] || [ -n "$(find "$dir" -maxdepth 0 -perm -0002)" ]; then echo "$dir can be written by anyone; put the swap file somewhere only root can" >&2; exit 1; fi
`
	if want := s.Bytes(); want > 0 {
		script += fmt.Sprintf(`if [ -e "$p" ] && { [ -L "$p" ] || [ ! -f "$p" ]; }; then echo "$p is there and isn't a regular file" >&2; exit 1; fi
if [ "$(stat -c %%s -- "$p" 2>/dev/null || echo 0)" != %[1]d ] || ! blkid -p -s TYPE -o value -- "$p" 2>/dev/null | grep -qx swap; then
  if [ -e "$p" ] && on; then swapoff -- "$p"; fi
  rm -f -- "$p"
  (umask 077; fallocate -l %[1]d -- "$p" 2>/dev/null || dd if=/dev/zero of="$p" bs=1M count=%[2]d status=none)
  chmod 600 -- "$p"
  mkswap -- "$p" >/dev/null
fi
chown root:root -- "$p"
chmod 600 -- "$p"
`, want, want>>20)
	} else {
		script += `[ -e "$p" ] || { echo "$p doesn't exist; set size to make a swap file there" >&2; exit 1; }
if ! on && ! blkid -p -s TYPE -o value -- "$p" 2>/dev/null | grep -qx swap; then echo "$p isn't swap; run mkswap on it first, which wipes what's on it" >&2; exit 1; fi
`
	}
	pri, flag := "", ""
	if s.Priority != "" {
		pri, flag = s.Priority, " -p "+s.Priority
	}
	script += fmt.Sprintf(`if on; then
  if [ -n %[1]s ] && [ "$(awk -v f="$(readlink -f -- "$p")" '$1==f{print $5}' /proc/swaps)" != %[1]s ]; then swapoff -- "$p"; swapon%[2]s -- "$p"; fi
else
  swapon%[2]s -- "$p"
fi
`, ssh.Quote(pri), flag)
	if err := check(r.Run(ctx, script, nil)); err != nil {
		return err
	}
	return writeFstab(ctx, r, edit.Line{Line: s.Line(), Regexp: s.entryRegexp()})
}

// DeleteSwap turns the swap off, removes its fstab entry, and removes a
// swap file Conn3x made.
func DeleteSwap(ctx context.Context, r modules.Runner, s Swap) error {
	script := "p=" + ssh.Quote(s.Path) + "\n" + `if [ -e "$p" ] && awk -v f="$(readlink -f -- "$p")" '$1==f{found=1} END{exit !found}' /proc/swaps; then swapoff -- "$p"; fi`
	if err := check(r.Run(ctx, script, nil)); err != nil {
		return err
	}
	if err := writeFstab(ctx, r, edit.Line{Regexp: s.entryRegexp(), State: edit.Absent}); err != nil || s.Size == "" {
		return err
	}
	return check(r.Run(ctx, "rm -f -- "+ssh.Quote(s.Path), nil))
}
