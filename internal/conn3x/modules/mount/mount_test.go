// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mount

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestValidate(t *testing.T) {
	for _, ok := range []Mount{
		{Path: "/mnt/scratch", Src: "tmpfs", FSType: "tmpfs", Opts: "size=16m,mode=0755"},
		{Path: "/data", Src: "UUID=0a1b2c3d-1111-2222-3333-444455556666", FSType: "xfs"},
		{Path: "/srv/nfs", Src: "nfs.example.com:/export", FSType: "nfs4", Opts: "_netdev"},
		{Path: "/data", Src: "LABEL=data", FSType: "xfs", Dump: 1, PassNo: 2},
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
		{Path: "/mnt/a", Src: "tmpfs", FSType: "tmpfs", Dump: 2},
		{Path: "/mnt/a", Src: "tmpfs", FSType: "tmpfs", PassNo: 3},
		{Path: "/mnt/a", Src: "tmpfs", FSType: "tmpfs", PassNo: -1},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// A failure names the fstab field it's about, so the provider can point at
// that field rather than at path.
func TestValidateNamesTheField(t *testing.T) {
	for _, c := range []struct {
		attr string
		m    Mount
	}{
		{"path", Mount{Path: "relative", Src: "tmpfs", FSType: "tmpfs"}},
		{"src", Mount{Path: "/mnt/a", Src: "", FSType: "tmpfs"}},
		{"fstype", Mount{Path: "/mnt/a", Src: "tmpfs", FSType: "tmp fs"}},
		{"opts", Mount{Path: "/mnt/a", Src: "tmpfs", FSType: "tmpfs", Opts: "a b"}},
		{"dump", Mount{Path: "/mnt/a", Src: "tmpfs", FSType: "tmpfs", Dump: 2}},
		{"passno", Mount{Path: "/mnt/a", Src: "tmpfs", FSType: "tmpfs", PassNo: 3}},
	} {
		var ve *ValidationError
		if err := c.m.Validate(); !errors.As(err, &ve) || ve.Attribute != c.attr {
			t.Errorf("Validate(%+v): want ValidationError on %q, got %v", c.m, c.attr, err)
		}
	}
}

func TestLine(t *testing.T) {
	if got := (Mount{Path: "/mnt/scratch", Src: "tmpfs", FSType: "tmpfs"}).Line(); got != "tmpfs /mnt/scratch tmpfs defaults 0 0" {
		t.Fatalf("got %q", got)
	}
	// The last two fields are dump's frequency and fsck's pass.
	if got := (Mount{Path: "/data", Src: "LABEL=data", FSType: "xfs", Dump: 1, PassNo: 2}).Line(); got != "LABEL=data /data xfs defaults 1 2" {
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

// host reads /etc/fstab natively and takes a write to it, prints findmnt
// and the swap state it's given, and fails the first command holding fail.
type host struct {
	fstab   string
	findmnt string // SOURCE FSTYPE, "" when nothing is mounted
	swap    string // what swapState prints
	fail    string
	ran     []string
}

func (h *host) ReadFile(_ context.Context, p string) (modules.FileStat, error) {
	return modules.FileStat{Exists: p == fstab, Regular: true, Mode: 0o644, Owner: "root", Group: "root", Content: []byte(h.fstab)}, nil
}

func (h *host) Run(_ context.Context, cmd string, stdin []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	switch {
	case h.fail != "" && strings.Contains(cmd, h.fail):
		return ssh.Result{ExitCode: 1, Stderr: []byte("boom\n")}, nil
	case stdin != nil:
		h.fstab = string(stdin)
	case strings.HasPrefix(cmd, "findmnt -n"):
		if h.findmnt == "" {
			return ssh.Result{ExitCode: 1}, nil
		}
		return ssh.Result{Stdout: []byte(h.findmnt + "\n")}, nil
	case strings.Contains(cmd, "real=$(readlink"):
		return ssh.Result{Stdout: []byte(h.swap)}, nil
	}
	return ssh.Result{}, nil
}

// has reports whether a command held s.
func (h *host) has(s string) bool {
	for _, c := range h.ran {
		if strings.Contains(c, s) {
			return true
		}
	}
	return false
}

var ctx = context.Background()

const reload = "systemctl daemon-reload"

var scratch = Mount{Path: "/mnt/scratch", Src: "tmpfs", FSType: "tmpfs", Opts: "size=16m"}

func TestRead(t *testing.T) {
	h := &host{fstab: "UUID=1 / xfs defaults 0 0\ntmpfs  /mnt/scratch tmpfs size=16m 0 0\n", findmnt: "tmpfs tmpfs"}
	a, err := Read(ctx, h, scratch)
	if err != nil || !scratch.InSync(a) {
		t.Fatalf("got %+v, %v", a, err)
	}
	h.findmnt = ""
	if a, err := Read(ctx, h, scratch); err != nil || a.Mounted || a.Entry == "" {
		t.Fatalf("unmounted: %+v, %v", a, err)
	}
}

// An fstab entry with another fsck pass is out of sync, so a change to
// passno is written by the next apply rather than read as already right.
func TestReadPassNo(t *testing.T) {
	h := &host{fstab: "LABEL=data  /data xfs defaults 0 2\n", findmnt: "/dev/vdb1 xfs"}
	data := Mount{Path: "/data", Src: "LABEL=data", FSType: "xfs", PassNo: 2}
	if a, err := Read(ctx, h, data); err != nil || !data.InSync(a) {
		t.Fatalf("passno 2 for an entry with 2: %+v, %v", a, err)
	}
	data.PassNo = 0
	if a, err := Read(ctx, h, data); err != nil || data.InSync(a) {
		t.Fatalf("passno 0 for an entry with 2: %+v, %v", a, err)
	}
}

func TestApply(t *testing.T) {
	line := scratch.Line() + "\n"
	for name, c := range map[string]struct {
		fstab, findmnt string
		script         string // what the mount command holds
	}{
		"new":            {"", "", "route_mkdir '\\''/mnt/scratch'\\'' && mount '\\''/mnt/scratch'\\''"},
		"new options":    {"tmpfs /mnt/scratch tmpfs size=8m 0 0\n", "tmpfs tmpfs", "mount -o remount '\\''/mnt/scratch'\\''"},
		"other mounted":  {line, "/dev/vdb1 xfs", "umount '\\''/mnt/scratch'\\'' && mount '\\''/mnt/scratch'\\''"},
		"in sync":        {line, "tmpfs tmpfs", "mount -o remount"},
		"other src line": {"/dev/vdb1 /mnt/scratch xfs defaults 0 0\n", "/dev/vdb1 xfs", "umount"},
	} {
		h := &host{fstab: c.fstab, findmnt: c.findmnt}
		if err := Apply(ctx, h, scratch); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if h.fstab != line {
			t.Errorf("%s: fstab %q, want %q", name, h.fstab, line)
		}
		// systemd is told only when fstab changed.
		if h.has(reload) != (c.fstab != line) {
			t.Errorf("%s: daemon-reload %v", name, h.has(reload))
		}
		if last := h.ran[len(h.ran)-1]; !strings.Contains(last, c.script) {
			t.Errorf("%s: want %q in\n%s", name, c.script, last)
		}
	}
}

func TestApplyErrors(t *testing.T) {
	h := &host{}
	if err := Apply(ctx, h, Mount{Path: "/", Src: "tmpfs", FSType: "tmpfs"}); err == nil || len(h.ran) != 0 {
		t.Errorf("a mount on / reached the host: %v, %q", err, h.ran)
	}
	// A findmnt that fails means nothing is mounted, and daemon-reload is
	// best effort, so neither is here.
	for _, fail := range []string{"mktemp", "&& mount"} {
		h := &host{fail: fail}
		if err := Apply(ctx, h, scratch); err == nil || err.Error() != "boom" {
			t.Errorf("%s failing: %v", fail, err)
		}
	}
}

func TestDelete(t *testing.T) {
	h := &host{fstab: "UUID=1 / xfs defaults 0 0\n" + scratch.Line() + "\n"}
	if err := Delete(ctx, h, scratch); err != nil {
		t.Fatal(err)
	}
	if h.fstab != "UUID=1 / xfs defaults 0 0\n" || !h.has("umount '\\''/mnt/scratch'\\''") || !h.has(reload) {
		t.Fatalf("fstab %q after %q", h.fstab, h.ran)
	}
	// Nothing to remove leaves fstab, and systemd, alone.
	h = &host{fstab: "UUID=1 / xfs defaults 0 0\n"}
	if err := Delete(ctx, h, scratch); err != nil || h.has(reload) {
		t.Fatalf("%v after %q", err, h.ran)
	}
	h = &host{fstab: scratch.Line() + "\n", fail: "umount"}
	if err := Delete(ctx, h, scratch); err == nil || h.fstab == "" {
		t.Fatalf("a failed unmount still removed the entry: %v, %q", err, h.fstab)
	}
}
