// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package facts reads what a host is: its OS, architecture, size and address.
package facts

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Facts describe a host.
type Facts struct {
	Family   string // "redhat" or "debian"
	ID       string // os-release ID, such as rocky or ubuntu
	Version  string // os-release VERSION_ID
	Arch     string // uname -m
	CPUs     int
	MemoryMB int
	IPv4     string // source address of the default route, or ""
}

const script = `. /etc/os-release
echo "id=$ID"
echo "version=$VERSION_ID"
echo "like=$ID_LIKE"
echo "arch=$(uname -m)"
echo "cpus=$(nproc)"
awk '/^MemTotal:/ { print "memory_kb=" $2 }' /proc/meminfo
ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }')
[ -n "$ip" ] || ip=$(hostname -I 2>/dev/null | awk '{ print $1 }')
echo "ipv4=$ip"`

// Gather reads the facts from a host.
func Gather(ctx context.Context, r modules.Runner) (Facts, error) {
	res, err := r.Run(ctx, script, nil)
	if err != nil {
		return Facts{}, err
	}
	if res.ExitCode != 0 {
		return Facts{}, fmt.Errorf("reading host facts: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return parse(string(res.Stdout))
}

func parse(out string) (Facts, error) {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = strings.TrimSpace(v)
		}
	}
	f := Facts{ID: kv["id"], Version: kv["version"], Arch: kv["arch"], IPv4: kv["ipv4"]}
	for _, id := range append([]string{f.ID}, strings.Fields(kv["like"])...) {
		switch id {
		case "rhel", "fedora", "centos", "rocky", "almalinux":
			f.Family = "redhat"
		case "debian", "ubuntu":
			f.Family = "debian"
		}
		if f.Family != "" {
			break
		}
	}
	if f.Family == "" {
		return f, fmt.Errorf("%s is not supported yet; Conn3x manages the Red Hat family and Debian and Ubuntu", f.ID)
	}
	var err error
	if f.CPUs, err = strconv.Atoi(kv["cpus"]); err != nil {
		return f, fmt.Errorf("reading the CPU count %q: %w", kv["cpus"], err)
	}
	kb, err := strconv.Atoi(kv["memory_kb"])
	if err != nil {
		return f, fmt.Errorf("reading the memory size %q: %w", kv["memory_kb"], err)
	}
	f.MemoryMB = kb / 1024
	return f, nil
}
