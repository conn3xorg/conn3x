// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package firewall opens and closes ports with firewalld or ufw.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

var word = regexp.MustCompile(`^[A-Za-z0-9_.+-]+$`)

// Firewalld is one service or port allowed in a firewalld zone, both in the
// running firewall and in its permanent configuration.
type Firewalld struct {
	Zone    string // empty means firewalld's default zone
	Service string
	Port    string // such as 8080/tcp or 60000-61000/udp
}

var firewalldPort = regexp.MustCompile(`^(\d+)(?:-(\d+))?/(tcp|udp|sctp|dccp)$`)

// Validate checks a rule before anything reaches the host.
func (f Firewalld) Validate() error {
	if f.Zone != "" && !word.MatchString(f.Zone) {
		return fmt.Errorf("zone %q is not a firewalld zone name", f.Zone)
	}
	switch {
	case (f.Service == "") == (f.Port == ""):
		return errors.New("set exactly one of service or port")
	case f.Service != "" && !word.MatchString(f.Service):
		return fmt.Errorf("service %q is not a firewalld service name", f.Service)
	case f.Port != "":
		m := firewalldPort.FindStringSubmatch(f.Port)
		if m == nil {
			return fmt.Errorf("port %q must look like 8080/tcp or 60000-61000/udp", f.Port)
		}
		return portRange(f.Port, m[1], m[2])
	}
	return nil
}

func portRange(spec, lo, hi string) error {
	a, _ := strconv.Atoi(lo)
	b := a
	if hi != "" {
		b, _ = strconv.Atoi(hi)
	}
	if a < 1 || b > 65535 || b < a {
		return fmt.Errorf("port %q is out of range 1 to 65535", spec)
	}
	return nil
}

// option renders firewall-cmd's flags for verb: add, remove or query.
func (f Firewalld) option(verb string) string {
	opt := fmt.Sprintf("--%s-service=%s", verb, ssh.Quote(f.Service))
	if f.Port != "" {
		opt = fmt.Sprintf("--%s-port=%s", verb, ssh.Quote(f.Port))
	}
	if f.Zone != "" {
		opt = "--zone=" + ssh.Quote(f.Zone) + " " + opt
	}
	return opt
}

const firewalldRunning = `firewall-cmd --state >/dev/null 2>&1 || { echo "firewalld is not running; add steps that install and start it first" >&2; exit 1; }`

// ReadFirewalld reports whether the rule is in the running firewall and in
// the permanent configuration.
func ReadFirewalld(ctx context.Context, r modules.Runner, f Firewalld) (runtime, permanent bool, err error) {
	q := f.option("query")
	res, err := r.Run(ctx, fmt.Sprintf("%s\nfirewall-cmd %s; firewall-cmd --permanent %s; true", firewalldRunning, q, q), nil)
	if err := check(res, err); err != nil {
		return false, false, err
	}
	answers := strings.Fields(string(res.Stdout))
	if len(answers) != 2 {
		return false, false, fmt.Errorf("firewall-cmd: %s", strings.TrimSpace(string(res.Stderr)+string(res.Stdout)))
	}
	return answers[0] == "yes", answers[1] == "yes", nil
}

// ApplyFirewalld adds the rule to, or removes it from, the running firewall
// and the permanent configuration.
func ApplyFirewalld(ctx context.Context, r modules.Runner, f Firewalld, present bool) error {
	if err := f.Validate(); err != nil {
		return err
	}
	verb := "remove"
	if present {
		verb = "add"
	}
	o := f.option(verb)
	res, err := r.Run(ctx, fmt.Sprintf("%s\nfirewall-cmd %s >/dev/null && firewall-cmd --permanent %s >/dev/null", firewalldRunning, o, o), nil)
	return check(res, err)
}

// UFWRule is one ufw rule for a port, optionally from one address or network.
type UFWRule struct {
	Action string // allow, deny, reject or limit
	Port   string // such as 22, 22/tcp or 6000:6007/tcp
	From   string // an address or CIDR; empty means anywhere
}

var ufwPort = regexp.MustCompile(`^(\d+)(?::(\d+))?(?:/(tcp|udp))?$`)

// Validate checks a rule before anything reaches the host.
func (u UFWRule) Validate() error {
	switch u.Action {
	case "allow", "deny", "reject", "limit":
	default:
		return fmt.Errorf("action must be allow, deny, reject or limit, not %q", u.Action)
	}
	m := ufwPort.FindStringSubmatch(u.Port)
	if m == nil {
		return fmt.Errorf("port %q must look like 22, 22/tcp or 6000:6007/tcp", u.Port)
	}
	if m[2] != "" && m[3] == "" {
		return fmt.Errorf("port range %q needs a protocol, such as %s/tcp", u.Port, u.Port)
	}
	if err := portRange(u.Port, m[1], m[2]); err != nil {
		return err
	}
	if u.From != "" && net.ParseIP(u.From) == nil {
		if _, _, err := net.ParseCIDR(u.From); err != nil {
			return fmt.Errorf("from %q is not an address or CIDR", u.From)
		}
	}
	return nil
}

// Spec renders the rule the way ufw itself prints it in "ufw show added".
func (u UFWRule) Spec() string {
	if u.From == "" {
		return u.Action + " " + u.Port
	}
	port, proto, _ := strings.Cut(u.Port, "/")
	spec := fmt.Sprintf("%s from %s to any port %s", u.Action, u.From, port)
	if proto != "" {
		spec += " proto " + proto
	}
	return spec
}

func ufwAdded(out string, u UFWRule) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "ufw "+u.Spec() {
			return true
		}
	}
	return false
}

// ReadUFW reports whether ufw has the rule, whether or not ufw is enabled.
func ReadUFW(ctx context.Context, r modules.Runner, u UFWRule) (bool, error) {
	res, err := r.Run(ctx, "ufw show added", nil)
	if err := check(res, err); err != nil {
		return false, fmt.Errorf("ufw: %w", err)
	}
	return ufwAdded(string(res.Stdout), u), nil
}

// ApplyUFW adds or deletes the rule. Spec contains only validated words, so
// it is safe to pass unquoted.
func ApplyUFW(ctx context.Context, r modules.Runner, u UFWRule, present bool) error {
	if err := u.Validate(); err != nil {
		return err
	}
	cmd := "ufw " + u.Spec()
	if !present {
		cmd = "ufw delete " + u.Spec()
	}
	res, err := r.Run(ctx, cmd, nil)
	return check(res, err)
}

func check(res ssh.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return errors.New(strings.TrimSpace(string(res.Stderr) + string(res.Stdout)))
	}
	return nil
}
