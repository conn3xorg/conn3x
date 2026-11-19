// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package selinux

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

// Port is a local SELinux port rule: Port, a number or a range such as
// 8080-8090, on Protocol gets Type, so a service of that type may bind it.
type Port struct {
	Port     string
	Protocol string // tcp, udp, dccp or sctp
	Type     string // such as http_port_t
}

// No leading zero: semanage stores 08081 as 8081, which would never read
// back as in sync.
var portRange = regexp.MustCompile(`^([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?$`)

// Validate checks a rule before anything reaches the host.
func (p Port) Validate() error {
	m := portRange.FindStringSubmatch(p.Port)
	if m == nil {
		return fmt.Errorf("port %q must be a number or a range such as 8080-8090, without leading zeros", p.Port)
	}
	lo, _ := strconv.Atoi(m[1])
	hi := lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return fmt.Errorf("port %q must be from 1 to 65535, the low end first", p.Port)
	}
	if !slices.Contains([]string{"tcp", "udp", "dccp", "sctp"}, p.Protocol) {
		return fmt.Errorf("protocol %q must be tcp, udp, dccp or sctp", p.Protocol)
	}
	if !ident.MatchString(p.Type) {
		return fmt.Errorf("setype %q is not an SELinux type", p.Type)
	}
	return nil
}

// skipDisabled ends a script with success on a host without SELinux,
// printing "disabled" so a read can tell. It asks selinuxenabled, as the
// circuits' guards did: /sys/fs/selinux shows through into a container,
// Debian's included, from an SELinux host's kernel.
const skipDisabled = `{ command -v selinuxenabled >/dev/null && selinuxenabled; } || { echo disabled; exit 0; }`

// ReadPort returns whether SELinux is on, and the type a local rule gives
// the port, or "" if no local rule exists for it.
func ReadPort(ctx context.Context, r modules.Runner, p Port) (enabled bool, typ string, err error) {
	res, err := r.Run(ctx, fmt.Sprintf("%s\n%s\nsemanage port -l -C", skipDisabled, semanage), nil)
	if err := check(res, err); err != nil {
		return false, "", err
	}
	if strings.TrimSpace(string(res.Stdout)) == "disabled" {
		return false, "", nil
	}
	return true, localPortType(string(res.Stdout), p), nil
}

// localPortType finds p's type in "semanage port -l -C" output, where each
// line is a type, a protocol and a comma-separated list of ports and ranges.
func localPortType(out string, p Port) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != p.Protocol {
			continue
		}
		for _, n := range strings.Split(strings.Join(fields[2:], ""), ",") {
			if n == p.Port {
				return fields[0]
			}
		}
	}
	return ""
}

// ApplyPort adds the rule, or changes it when the port is already defined,
// by the policy or a local rule. On a host without SELinux it does nothing.
func ApplyPort(ctx context.Context, r modules.Runner, p Port) error {
	if err := p.Validate(); err != nil {
		return err
	}
	t, pr, n := ssh.Quote(p.Type), ssh.Quote(p.Protocol), ssh.Quote(p.Port)
	script := fmt.Sprintf("%s\n%s\nsemanage port -a -t %s -p %s %s 2>/dev/null || semanage port -m -t %s -p %s %s", skipDisabled, semanage, t, pr, n, t, pr, n)
	res, err := r.Run(ctx, script, nil)
	return check(res, err)
}

// DeletePort removes the local rule, leaving whatever the policy says.
func DeletePort(ctx context.Context, r modules.Runner, p Port) error {
	script := fmt.Sprintf("%s\n%s\nsemanage port -d -p %s %s", skipDisabled, semanage, ssh.Quote(p.Protocol), ssh.Quote(p.Port))
	res, err := r.Run(ctx, script, nil)
	return check(res, err)
}
