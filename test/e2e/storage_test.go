// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The storage steps on real block devices: a volume group, a logical volume
// that grows and won't shrink, and a file system that grows with it and
// won't be made over another. Containers can't make loop devices, so this
// runs only when CONN3X_E2E_LOOPS names two the container may use, as
// root:
//
//	podman machine ssh 'sudo truncate -s 1G /var/tmp/a.img /var/tmp/b.img; sudo losetup -f --show /var/tmp/a.img; sudo losetup -f --show /var/tmp/b.img'
//	CONTAINER_CONNECTION=podman-machine-default-root CONN3X_E2E_LOOPS=/dev/loop0,/dev/loop1 go test -tags e2e ./test/e2e -run TestStorage
func TestStorageOnLoopDevices(t *testing.T) {
	loops := strings.Split(os.Getenv("CONN3X_E2E_LOOPS"), ",")
	if len(loops) != 2 {
		t.Skip("set CONN3X_E2E_LOOPS to two loop devices; see the comment above")
	}
	box := startHostWith(t, "rocky10", "--privileged", "--device", loops[0], "--device", loops[1])
	// Start from blank devices, whatever an earlier run left on them.
	box.exec("", "wipefs", "-a", loops[0], loops[1])
	// No udev in a container: LVM makes its own device nodes.
	box.exec("", "sh", "-c", "mkdir -p /etc/lvm && printf 'activation {\\n udev_sync = 0\\n udev_rules = 0\\n}\\n' > /etc/lvm/lvm.conf")
	// The volume's device-mapper device belongs to the machine's kernel, not
	// the container, so it would outlive the container and keep the loop
	// devices busy.
	t.Cleanup(func() { _ = exec.Command("podman", "exec", box.container, "vgchange", "-an", "c3vg").Run() })
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "storage")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	one := `-var=pvs=["` + loops[0] + `"]`
	both := `-var=pvs=["` + loops[0] + `","` + loops[1] + `"]`
	lvSize := func() string {
		return strings.TrimSpace(box.exec("", "lvs", "--noheadings", "--units", "m", "--nosuffix", "-o", "lv_size", "c3vg/data"))
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=size=200m", one)
	if got := lvSize(); got != "200.00" {
		t.Errorf("lv size = %s, want 200.00", got)
	}
	if got := strings.TrimSpace(box.exec("", "blkid", "-o", "value", "-s", "TYPE", "/dev/c3vg/data")); got != "ext4" {
		t.Errorf("file system = %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=size=200m", one); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}

	// Grow the group and the volume; the file system follows.
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=size=1200m", both)
	if got := lvSize(); got != "1200.00" {
		t.Errorf("lv size after growing = %s", got)
	}
	blocks := box.exec("", "sh", "-c", "dumpe2fs -h /dev/c3vg/data 2>/dev/null | awk -F: '/^Block count/{c=$2} /^Block size/{s=$2} END{printf \"%.0f\", c*s/1048576}'")
	if strings.TrimSpace(blocks) != "1200" {
		t.Errorf("file system is %s MiB after growing, want 1200", blocks)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=size=1200m", both); !strings.Contains(out, "No changes") {
		t.Errorf("a plan after growing should be clean:\n%s", out)
	}

	// Nothing shrinks or reformats without force.
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color", "-var=size=100m", both); code == 0 || !strings.Contains(out, "set force = true") {
		t.Errorf("shrinking should be refused (exit %d):\n%s", code, out)
	}
	if got := lvSize(); got != "1200.00" {
		t.Errorf("the volume shrank to %s", got)
	}
	if out, code := w.conn3x("apply", "-auto-approve", "-no-color", "-var=size=1200m", both, "-var=fs_type=xfs"); code == 0 || !strings.Contains(out, "already holds a ext4 file system") {
		t.Errorf("making xfs over ext4 should be refused (exit %d):\n%s", code, out)
	}
}
