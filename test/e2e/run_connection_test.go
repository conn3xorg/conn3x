// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conn3x run reaches an inventory host with ansible_connection=podman
// through podman exec, and one with local on this machine, with no SSH.
func TestRunAnsibleConnection(t *testing.T) {
	h := startHost(t, "debian13")
	w := &workdir{t: t, dir: t.TempDir()}
	inv := "box ansible_connection=containers.podman.podman ansible_host=" + h.container + " ansible_user=root\nhere ansible_connection=local\n"
	if err := os.WriteFile(filepath.Join(w.dir, "hosts.ini"), []byte(inv), 0o644); err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(h.exec("", "cat", "/etc/hostname"))
	out, code := w.conn3x("run", "-i", "hosts.ini", "box", "-a", "cat /etc/hostname")
	if code != 0 || !strings.Contains(out, "box | changed") || !strings.Contains(out, "  "+want) {
		t.Errorf("podman host (exit %d), want %s:\n%s", code, want, out)
	}
	marker := filepath.Join(w.dir, "ran-here")
	out, code = w.conn3x("run", "-i", "hosts.ini", "here", "-a", "touch "+marker)
	if _, err := os.Stat(marker); code != 0 || err != nil {
		t.Errorf("local host (exit %d, %v):\n%s", code, err, out)
	}
	if err := os.WriteFile(filepath.Join(w.dir, "locked.ini"), []byte("locked ansible_connection=local ansible_become=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := w.conn3x("run", "-i", "locked.ini", "all", "-a", "true"); code == 0 || !strings.Contains(out, "can't become root") {
		t.Errorf("local with become (exit %d):\n%s", code, out)
	}
}
