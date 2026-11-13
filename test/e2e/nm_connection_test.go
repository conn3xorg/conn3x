// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// An nm_connection step on a veth pair, with NetworkManager and udev
// running in a privileged container: brought up behind its revert timer,
// changed, put back after an nmcli edit, and deleted.
func TestNMConnection(t *testing.T) {
	box := startHostWith(t, "rocky10", "--privileged")
	box.exec("", "sh", "-c", `dnf -y -q install NetworkManager iproute systemd-udev >/dev/null &&
systemctl unmask systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket >/dev/null 2>&1 &&
systemctl start systemd-udevd &&
ip link add c3a type veth peer name c3b && ip link set c3b up &&
udevadm trigger --action=add --subsystem-match=net && udevadm settle &&
systemctl start NetworkManager`)
	knownFile := shareKey(t, box)
	w := newWorkdir(t, "nm_connection")
	w.writeAs("main.circuit.hcl", chainVars{PortA: box.port, Key: box.keyFile, KnownHosts: knownFile})
	w.mustConn3x("init", "-no-color")
	addr := func() string {
		return strings.TrimSpace(box.exec("", "sh", "-c", "ip -4 -o addr show c3a | awk '{print $4}'"))
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=address=192.0.2.10/24")
	if got := addr(); got != "192.0.2.10/24" {
		t.Fatalf("c3a has %q", got)
	}
	if mode := strings.TrimSpace(box.exec("", "stat", "-c", "%a %U", "/etc/NetworkManager/system-connections/lan.nmconnection")); mode != "600 root" {
		t.Errorf("keyfile mode = %q", mode)
	}
	if out := box.exec("", "ls", "/var/lib/conn3x/revert"); strings.TrimSpace(out) != "" {
		t.Errorf("the revert should be cancelled once confirmed, found %q", out)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=address=192.0.2.11/24")
	if got := addr(); got != "192.0.2.11/24" {
		t.Errorf("after changing the address, c3a has %q", got)
	}
	if out := w.mustConn3x("plan", "-no-color", "-var=address=192.0.2.11/24"); !strings.Contains(out, "No changes") {
		t.Errorf("a second plan should be clean:\n%s", out)
	}

	box.exec("", "nmcli", "connection", "modify", "lan", "ipv4.addresses", "192.0.2.99/24")
	if out := w.mustConn3x("plan", "-no-color", "-var=address=192.0.2.11/24"); !strings.Contains(out, "1 to change") {
		t.Errorf("an nmcli edit should show as a change:\n%s", out)
	}
	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=address=192.0.2.11/24")
	if got := addr(); got != "192.0.2.11/24" {
		t.Errorf("after putting it back, c3a has %q", got)
	}

	w.mustConn3x("apply", "-auto-approve", "-no-color", "-var=address=192.0.2.11/24", "-var=present=false")
	if out := box.exec("", "sh", "-c", "nmcli -t -f NAME connection show; ls /etc/NetworkManager/system-connections"); strings.Contains(out, "lan") {
		t.Errorf("on_remove = delete should remove the profile:\n%s", out)
	}
}
