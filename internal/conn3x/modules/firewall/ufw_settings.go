// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/opentofu/opentofu/internal/conn3x/modules"
)

// UFWSettings is ufw itself: whether it's on, its default policy for
// each direction, and its logging level. Anything unset is left as it is.
type UFWSettings struct {
	Enabled                    *bool
	Incoming, Outgoing, Routed string // allow, deny or reject; "" leaves it
	Logging                    string // off, on, low, medium, high or full; "" leaves it
}

// UFWState is ufw as the host has it.
type UFWState struct {
	Active                     bool // running, and enabled at boot
	Incoming, Outgoing, Routed string
	Logging                    string // LOGLEVEL in /etc/ufw/ufw.conf; "" when it's missing
}

// Validate checks the settings before anything reaches the host.
func (s UFWSettings) Validate() error {
	if s.Enabled == nil && s.Incoming == "" && s.Outgoing == "" && s.Routed == "" && s.Logging == "" {
		return errors.New("set enabled, a default policy or logging: a ufw_settings step with nothing set does nothing")
	}
	switch s.Logging {
	case "", "off", "on", "low", "medium", "high", "full":
	default:
		return fmt.Errorf("logging must be off, on, low, medium, high or full, not %q", s.Logging)
	}
	for dir, p := range map[string]string{"default_incoming": s.Incoming, "default_outgoing": s.Outgoing, "default_routed": s.Routed} {
		switch p {
		case "", "allow", "deny", "reject":
		default:
			return fmt.Errorf("%s must be allow, deny or reject, not %q", dir, p)
		}
	}
	return nil
}

// Matches reports whether the host has every setting s sets.
func (s UFWSettings) Matches(st UFWState) bool {
	return (s.Enabled == nil || *s.Enabled == st.Active) &&
		(s.Incoming == "" || s.Incoming == st.Incoming) &&
		(s.Outgoing == "" || s.Outgoing == st.Outgoing) &&
		(s.Routed == "" || s.Routed == st.Routed) &&
		s.loggingMatches(st.Logging)
}

// loggingMatches reports whether ufw logs as s asks. on is any level but
// off, as ufw logging on keeps the level it has and sets low only from off.
func (s UFWSettings) loggingMatches(have string) bool {
	if s.Logging == "on" {
		return have != "" && have != "off"
	}
	return s.Logging == "" || s.Logging == have
}

// The policies come from /etc/default/ufw, not ufw status, which shows
// none while ufw is off, and shows routed as disabled while the host
// doesn't forward.
const ufwStateScript = `policy() { sed -n "s/^$1=[\"']*\([A-Z]*\)[\"']*$/\1/p" /etc/default/ufw | tail -n 1; }
echo "incoming=$(policy DEFAULT_INPUT_POLICY)"
echo "outgoing=$(policy DEFAULT_OUTPUT_POLICY)"
echo "routed=$(policy DEFAULT_FORWARD_POLICY)"
echo "logging=$(sed -n "s/^LOGLEVEL=[\"']*\([a-z]*\)[\"']*$/\1/p" /etc/ufw/ufw.conf | tail -n 1)"
echo "boot=$(sed -n "s/^ENABLED=[\"']*\([a-z]*\)[\"']*$/\1/p" /etc/ufw/ufw.conf | tail -n 1)"
echo "status=$(ufw status | head -n 1)"`

// ReadUFWState reads whether ufw is on and its default policies.
func ReadUFWState(ctx context.Context, r modules.Runner) (UFWState, error) {
	res, err := r.Run(ctx, ufwStateScript, nil)
	if err := check(res, err); err != nil {
		return UFWState{}, fmt.Errorf("ufw: %w", err)
	}
	return parseUFWState(string(res.Stdout))
}

var ufwPolicies = map[string]string{"ACCEPT": "allow", "DROP": "deny", "REJECT": "reject"}

func parseUFWState(out string) (UFWState, error) {
	var st UFWState
	var boot, status string
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "incoming", "outgoing", "routed":
			p, ok := ufwPolicies[v]
			if !ok {
				return UFWState{}, fmt.Errorf("can't read ufw's default %s policy from /etc/default/ufw: %q", k, v)
			}
			switch k {
			case "incoming":
				st.Incoming = p
			case "outgoing":
				st.Outgoing = p
			default:
				st.Routed = p
			}
		case "logging":
			st.Logging = v
		case "boot":
			boot = v
		case "status":
			status = v
		}
	}
	if st.Incoming == "" || st.Outgoing == "" || st.Routed == "" {
		return UFWState{}, errors.New("can't read ufw's default policies from /etc/default/ufw")
	}
	st.Active = status == "Status: active" && boot == "yes"
	return st, nil
}

// Commands are what makes the host match s from st, policies first, so
// ufw comes up with them, and the undo that takes them back.
func (s UFWSettings) Commands(st UFWState) (do, undo []string) {
	for _, d := range []struct{ want, have, dir string }{{s.Incoming, st.Incoming, "incoming"}, {s.Outgoing, st.Outgoing, "outgoing"}, {s.Routed, st.Routed, "routed"}} {
		if d.want != "" && d.want != d.have {
			do = append(do, "flock /run/conn3x-ufw.lock ufw default "+d.want+" "+d.dir)
			undo = append(undo, "flock /run/conn3x-ufw.lock ufw default "+d.have+" "+d.dir)
		}
	}
	if !s.loggingMatches(st.Logging) {
		do = append(do, "flock /run/conn3x-ufw.lock ufw logging "+s.Logging)
		// With no LOGLEVEL in ufw.conf there's no level to put back.
		if st.Logging != "" {
			undo = append(undo, "flock /run/conn3x-ufw.lock ufw logging "+st.Logging)
		}
	}
	if s.Enabled != nil && *s.Enabled != st.Active {
		on, off := "flock /run/conn3x-ufw.lock ufw --force enable", "flock /run/conn3x-ufw.lock ufw disable"
		if *s.Enabled {
			do, undo = append(do, on), append([]string{off}, undo...)
		} else {
			do, undo = append(do, off), append([]string{on}, undo...)
		}
	}
	return do, undo
}

// SSHPeer is where the SSH connection Conn3x is using comes from, as sshd
// puts it in $SSH_CONNECTION: a nil Client when that can't be read.
type SSHPeer struct {
	Client net.IP
	Local  bool // over loopback, which ufw always lets in
}

// ParseSSHConnection reads $SSH_CONNECTION: client address and port, then
// server address and port. A client at the server's own address arrives
// over loopback, as a forwarded port in a container does.
func ParseSSHConnection(v string) SSHPeer {
	f := strings.Fields(v)
	if len(f) != 4 {
		return SSHPeer{}
	}
	client, server := net.ParseIP(f[0]), net.ParseIP(f[2])
	if client == nil {
		return SSHPeer{}
	}
	return SSHPeer{Client: client, Local: client.IsLoopback() || client.Equal(server)}
}

// LocksOut reports whether applying s to st would leave ufw running with
// incoming traffic refused, by a change s makes, while no ufw rule lets
// this connection in to sshd's port: the next login would never arrive.
func (s UFWSettings) LocksOut(st UFWState, added string, sshPorts []int, peer SSHPeer) bool {
	active := st.Active
	if s.Enabled != nil {
		active = *s.Enabled
	}
	incoming := st.Incoming
	if s.Incoming != "" {
		incoming = s.Incoming
	}
	changes := active != st.Active || incoming != st.Incoming
	if !active || incoming == "allow" || !changes {
		return false
	}
	return !slices.ContainsFunc(sshPorts, func(p int) bool { return ufwLetsIn(added, p, peer) })
}

// ufwLetsIn reports whether a rule in "ufw show added" allows or limits
// TCP to port for peer. A rule with a from counts only when it covers the
// peer, or the peer is local, since SSH allowed from an admin network
// while Conn3x runs from somewhere else is how people get shut out.
func ufwLetsIn(added string, port int, peer SSHPeer) bool {
	for _, line := range strings.Split(added, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "ufw" || (f[1] != "allow" && f[1] != "limit") {
			continue
		}
		f = f[2:]
		if f[0] == "in" {
			f = f[1:]
		}
		if len(f) == 0 || f[0] == "out" {
			continue
		}
		if i := slices.Index(f, "from"); i >= 0 && i+1 < len(f) && f[i+1] != "any" && !peer.Local && !covers(f[i+1], peer.Client) {
			continue
		}
		spec := f[0]
		if i := slices.Index(f, "port"); i >= 0 && i+1 < len(f) {
			spec = f[i+1]
			if j := slices.Index(f, "proto"); j >= 0 && j+1 < len(f) && f[j+1] != "tcp" {
				continue
			}
		}
		if (spec == "OpenSSH" || spec == "ssh") && port == 22 || portIn(spec, port) {
			return true
		}
	}
	return false
}

// covers reports whether a ufw from, an address or a network, takes ip.
func covers(from string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	if _, n, err := net.ParseCIDR(from); err == nil {
		return n.Contains(ip)
	}
	a := net.ParseIP(from)
	return a != nil && a.Equal(ip)
}

// portIn reports whether a ufw port spec such as 22, 22/tcp or
// 6000:6007/tcp takes TCP to port.
func portIn(spec string, port int) bool {
	ports, proto, _ := strings.Cut(spec, "/")
	if proto != "" && proto != "tcp" {
		return false
	}
	for _, part := range strings.Split(ports, ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 == nil && err2 == nil && a <= port && port <= b {
			return true
		}
	}
	return false
}

// SSHPorts are the ports sshd listens on, by its own reading of its
// config, or 22 when it can't say.
func SSHPorts(ctx context.Context, r modules.Runner) []int {
	res, err := r.Run(ctx, `sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'`, nil)
	var ports []int
	if err == nil && res.ExitCode == 0 {
		for _, f := range strings.Fields(string(res.Stdout)) {
			if p, err := strconv.Atoi(f); err == nil {
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}

// ReadUFWAdded is "ufw show added": the rules, whether or not ufw is on.
func ReadUFWAdded(ctx context.Context, r modules.Runner) (string, error) {
	res, err := r.Run(ctx, "ufw show added", nil)
	if err := check(res, err); err != nil {
		return "", fmt.Errorf("ufw: %w", err)
	}
	return string(res.Stdout), nil
}

// ApplyUFWSettings runs do, then reads ufw back.
func ApplyUFWSettings(ctx context.Context, r modules.Runner, s UFWSettings, do []string) error {
	for _, cmd := range do {
		res, err := r.Run(ctx, cmd, nil)
		if err := check(res, err); err != nil {
			return fmt.Errorf("%s: %w", strings.TrimPrefix(cmd, "flock /run/conn3x-ufw.lock "), err)
		}
	}
	st, err := ReadUFWState(ctx, r)
	if err != nil {
		return err
	}
	if !s.Matches(st) {
		return fmt.Errorf("ufw doesn't match after applying: active %t, default %s (incoming), %s (outgoing), %s (routed), logging %q", st.Active, st.Incoming, st.Outgoing, st.Routed, st.Logging)
	}
	return nil
}
