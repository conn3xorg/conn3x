// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package facts reads what a host is: its OS, architecture, size and address.
package facts

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// Facts describe a host.
type Facts struct {
	Family   string // "redhat" or "debian"
	ID       string // os-release ID, such as rocky or ubuntu
	Version  string // os-release VERSION_ID
	Codename string // os-release VERSION_CODENAME, or UBUNTU_CODENAME, or ""
	// ServiceManager is what Ansible's service_mgr reads on Linux, such as
	// systemd, or "" when it can't tell.
	ServiceManager string
	Arch           string // uname -m
	CPUs           int
	MemoryMB       int
	IPv4           string // source address of the default route, or ""
}

// codenameLine prints the release codename as Ansible's
// get_distribution_codename reads it from os-release: VERSION_CODENAME,
// and UBUNTU_CODENAME only when VERSION_CODENAME isn't set at all, since
// a distribution with no codenames may set it empty.
const codenameLine = `echo "codename=${VERSION_CODENAME-$UBUNTU_CODENAME}"`

// serviceManager prints the service manager under the root in $1 in the
// order Ansible's service_mgr.py checks for it on Linux: PID 1's name,
// unless that's init or a shell, renamed as Ansible renames it; then
// systemd when systemctl is installed and one of sd_booted's directories
// exists, or /sbin/init links to systemd. Ansible's upstart, openrc,
// sysvinit and dinit checks, and its fallback "service", are left out:
// nothing prints instead.
const serviceManager = `service_manager() {
	p=$(cat "$1/proc/1/comm" 2>/dev/null)
	case $p in
	'' | init | *sh) ;;
	procd) echo openwrt_init; return ;;
	runit-init) echo runit; return ;;
	svscan) echo svc; return ;;
	openrc-init) echo openrc; return ;;
	*) echo "$p"; return ;;
	esac
	command -v systemctl >/dev/null 2>&1 || return 0
	for d in /run/systemd/system /dev/.run/systemd /dev/.systemd; do
		[ -e "$1$d" ] && { echo systemd; return; }
	done
	l=$(readlink "$1/sbin/init" 2>/dev/null)
	[ "${l##*/}" != systemd ] || echo systemd
}
`

const script = `. /etc/os-release
echo "id=$ID"
echo "version=$VERSION_ID"
` + codenameLine + `
` + serviceManager + `echo "service_manager=$(service_manager)"
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

// What os-release allows for ID, VERSION_ID and VERSION_CODENAME, and
// what uname -m prints.
var (
	idWord      = regexp.MustCompile(`^[a-z0-9._-]+$`)
	versionWord = regexp.MustCompile(`^[A-Za-z0-9._-]*$`)
	archWord    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// Plain refuses a fact that isn't the plain word it should be. The host
// reports its own facts, and a circuit may put one into a command for
// another host, so a fact never carries shell syntax or control characters.
func Plain(f Facts) error {
	switch {
	case !idWord.MatchString(f.ID):
		return fmt.Errorf("the host reported an OS id that isn't a plain word: %q", f.ID)
	case !versionWord.MatchString(f.Version):
		return fmt.Errorf("the host reported an OS version that isn't a plain word: %q", f.Version)
	case !versionWord.MatchString(f.Codename):
		return fmt.Errorf("the host reported a release codename that isn't a plain word: %q", f.Codename)
	case !archWord.MatchString(f.Arch):
		return fmt.Errorf("the host reported an architecture that isn't a plain word: %q", f.Arch)
	}
	if f.IPv4 != "" {
		if a, err := netip.ParseAddr(f.IPv4); err != nil || !a.Is4() {
			return fmt.Errorf("the host reported an IPv4 address that isn't one: %q", f.IPv4)
		}
	}
	return nil
}

func parse(out string) (Facts, error) {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			kv[k] = strings.TrimSpace(v)
		}
	}
	f := Facts{ID: kv["id"], Version: kv["version"], Codename: kv["codename"], Arch: kv["arch"], IPv4: kv["ipv4"]}
	if err := Plain(f); err != nil {
		return Facts{}, err
	}
	// PID 1 can be any program, and an odd name shouldn't fail the read.
	if sm := kv["service_manager"]; versionWord.MatchString(sm) {
		f.ServiceManager = sm
	}
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
