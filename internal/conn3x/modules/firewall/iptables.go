// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

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

// IPTablesRule is one iptables or ip6tables rule in one chain, matched by
// its whole spec, the way iptables -C matches it.
type IPTablesRule struct {
	Table, Chain                string // Table empty means filter
	Protocol                    string
	Source, Destination         string // an address or CIDR
	SourcePort, DestinationPort string // 22 or 6000:6007
	DestinationPorts            []string
	InInterface, OutInterface   string
	CTState                     []string
	Jump, Comment               string
	IPv6                        bool
	Insert                      bool // -I instead of -A when the rule is added
	RuleNum                     int  // with Insert, the position; 0 means the top
	Persist                     bool // save the table for the boot loader after each change
}

var (
	iptPort      = regexp.MustCompile(`^(\d+)(?::(\d+))?$`)
	iptInterface = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}\+?$`)
	ctStates     = map[string]bool{"INVALID": true, "NEW": true, "ESTABLISHED": true, "RELATED": true, "UNTRACKED": true, "SNAT": true, "DNAT": true}
	portProtos   = map[string]bool{"tcp": true, "udp": true, "udplite": true, "sctp": true, "dccp": true}
)

// Validate checks a rule before anything reaches the host.
func (r IPTablesRule) Validate() error {
	switch r.Table {
	case "", "filter", "nat", "mangle", "raw", "security":
	default:
		return fmt.Errorf("table must be filter, nat, mangle, raw or security, not %q", r.Table)
	}
	if !word.MatchString(r.Chain) || len(r.Chain) > 28 {
		return fmt.Errorf("chain %q is not an iptables chain name", r.Chain)
	}
	if r.Protocol != "" && !word.MatchString(r.Protocol) {
		return fmt.Errorf("protocol %q is not a protocol name or number", r.Protocol)
	}
	for what, a := range map[string]string{"source": r.Source, "destination": r.Destination} {
		if err := r.address(what, a); err != nil {
			return err
		}
	}
	ports := map[string]string{"source_port": r.SourcePort, "destination_port": r.DestinationPort}
	for i, p := range r.DestinationPorts {
		ports[fmt.Sprintf("destination_ports[%d]", i)] = p
	}
	for what, p := range ports {
		if p == "" {
			continue
		}
		m := iptPort.FindStringSubmatch(p)
		if m == nil {
			return fmt.Errorf("%s %q must be a port, such as 22, or a range, such as 6000:6007", what, p)
		}
		if err := portRange(p, m[1], m[2]); err != nil {
			return err
		}
		if !portProtos[r.Protocol] {
			return fmt.Errorf("%s needs protocol set to tcp, udp, udplite, sctp or dccp", what)
		}
	}
	if r.DestinationPort != "" && len(r.DestinationPorts) > 0 {
		return errors.New("set destination_port or destination_ports, not both")
	}
	if len(r.DestinationPorts) > 15 {
		return fmt.Errorf("destination_ports has %d ports; iptables' multiport takes 15 at most", len(r.DestinationPorts))
	}
	for what, i := range map[string]string{"in_interface": r.InInterface, "out_interface": r.OutInterface} {
		if i != "" && !iptInterface.MatchString(i) {
			return fmt.Errorf("%s %q is not an interface name", what, i)
		}
	}
	for _, s := range r.CTState {
		if !ctStates[s] {
			return fmt.Errorf("ctstate %q must be one of INVALID, NEW, ESTABLISHED, RELATED, UNTRACKED, SNAT or DNAT", s)
		}
	}
	if r.Jump != "" && (!word.MatchString(r.Jump) || len(r.Jump) > 28) {
		return fmt.Errorf("jump %q is not a target or chain name", r.Jump)
	}
	if len(r.Comment) > 256 || strings.ContainsAny(r.Comment, "\r\n\x00") {
		return errors.New("comment must be one line of at most 256 characters")
	}
	if r.RuleNum < 0 || r.RuleNum > 0 && !r.Insert {
		return errors.New(`rule_num is a position from 1 up, and only for position = "insert"`)
	}
	return nil
}

// address checks a source or destination is an address or network of the
// rule's IP version. A host name or a comma list would make iptables add
// one rule per address, which -C and -D don't handle as one.
func (r IPTablesRule) address(what, a string) error {
	if a == "" {
		return nil
	}
	ip := net.ParseIP(a)
	if ip == nil {
		var err error
		if ip, _, err = net.ParseCIDR(a); err != nil {
			return fmt.Errorf("%s %q is not an address or CIDR", what, a)
		}
	}
	if (ip.To4() == nil) != r.IPv6 {
		return fmt.Errorf("%s %q is not an %s address; set ip_version to match", what, a, r.version())
	}
	return nil
}

func (r IPTablesRule) version() string {
	if r.IPv6 {
		return "ipv6"
	}
	return "ipv4"
}

func (r IPTablesRule) binary() string {
	if r.IPv6 {
		return "ip6tables"
	}
	return "iptables"
}

func (r IPTablesRule) table() string {
	if r.Table == "" {
		return "filter"
	}
	return r.Table
}

// Spec is the rule's match and target, in the order iptables takes them.
func (r IPTablesRule) Spec() []string {
	var a []string
	add := func(flag, v string) {
		if v != "" {
			a = append(a, flag, v)
		}
	}
	add("-p", r.Protocol)
	add("-s", r.Source)
	add("-d", r.Destination)
	add("-i", r.InInterface)
	add("-o", r.OutInterface)
	add("--sport", r.SourcePort)
	add("--dport", r.DestinationPort)
	if len(r.DestinationPorts) > 0 {
		a = append(a, "-m", "multiport", "--dports", strings.Join(r.DestinationPorts, ","))
	}
	if len(r.CTState) > 0 {
		a = append(a, "-m", "conntrack", "--ctstate", strings.Join(r.CTState, ","))
	}
	if r.Comment != "" {
		a = append(a, "-m", "comment", "--comment", r.Comment)
	}
	add("-j", r.Jump)
	return a
}

// command is iptables or ip6tables with op (-C, -A, -I or -D) on the
// rule, every word quoted. -w waits for the xtables lock, so rules from a
// step with for_each take turns.
func (r IPTablesRule) command(op string) string {
	words := []string{r.binary(), "-w", "-t", r.table(), op, r.Chain}
	if op == "-I" && r.RuleNum > 0 {
		words = append(words, strconv.Itoa(r.RuleNum))
	}
	return quoteAll(append(words, r.Spec()...))
}

func quoteAll(words []string) string {
	q := make([]string, len(words))
	for i, w := range words {
		q[i] = ssh.Quote(w)
	}
	return strings.Join(q, " ")
}

// ReadIPTables reports whether the running firewall has the rule, by the
// exit status of iptables -C: 0 has it, 1 with "Bad rule" hasn't. Any
// other failure, a missing chain among them, is an error, never a guess.
func ReadIPTables(ctx context.Context, r modules.Runner, rule IPTablesRule) (bool, error) {
	if err := rule.Validate(); err != nil {
		return false, err
	}
	res, err := r.Run(ctx, rule.command("-C"), nil)
	if err != nil {
		return false, err
	}
	out := string(res.Stderr) + string(res.Stdout)
	switch res.ExitCode {
	case 0:
		return true, nil
	case 1:
		if strings.Contains(out, "Bad rule") {
			return false, nil
		}
	case 127:
		return false, fmt.Errorf("%s isn't on this host: install the iptables package, for example with a package step before this one", rule.binary())
	}
	return false, fmt.Errorf("%s -C: %s", rule.binary(), strings.TrimSpace(out))
}

// ApplyIPTables adds the rule when present and it's missing, or deletes it
// when not present and it's there, then saves the table when Persist is set.
func ApplyIPTables(ctx context.Context, r modules.Runner, rule IPTablesRule, present bool) error {
	has, err := ReadIPTables(ctx, r, rule)
	if err != nil {
		return err
	}
	if has != present {
		if err := check(r.Run(ctx, rule.change(present), nil)); err != nil {
			return err
		}
	}
	if rule.Persist {
		return check(r.Run(ctx, rule.SaveCommand(), nil))
	}
	return nil
}

// change is the command that adds the rule, or deletes it.
func (r IPTablesRule) change(present bool) string {
	switch {
	case !present:
		return r.command("-D")
	case r.Insert:
		return r.command("-I")
	}
	return r.command("-A")
}

// Undo is what takes back ApplyIPTables(rule, present) on a host that had
// the rule (had) or not: nothing when the apply changes nothing.
func (r IPTablesRule) Undo(present, had bool) []string {
	if had == present {
		return nil
	}
	cmds := []string{r.change(!present)}
	if r.Persist {
		cmds = append(cmds, r.SaveCommand())
	}
	return cmds
}

// SaveCommand writes iptables-save, or ip6tables-save, to the file the
// boot loader reads: /etc/iptables/rules.v4 or rules.v6 with Debian's
// iptables-persistent, /etc/sysconfig/iptables or ip6tables with the Red
// Hat family's iptables-services. It's written beside the file and moved
// over it, so a failed save leaves the old one. With neither loader on
// the host, it fails rather than write a file nothing reads.
func (r IPTablesRule) SaveCommand() string {
	deb, rh, plugin, init := "/etc/iptables/rules.v4", "/etc/sysconfig/iptables", "15-ip4tables", "iptables.init"
	if r.IPv6 {
		deb, rh, plugin, init = "/etc/iptables/rules.v6", "/etc/sysconfig/ip6tables", "25-ip6tables", "ip6tables.init"
	}
	return fmt.Sprintf(`if [ -e /usr/share/netfilter-persistent/plugins.d/%s ]; then f=%s; `+
		`elif [ -e /usr/libexec/iptables/%s ]; then f=%s; `+
		`else echo "persist needs iptables-persistent (Debian, Ubuntu) or iptables-services (Red Hat family) on the host to load the saved rules at boot; install it with a package step before this one" >&2; exit 1; fi; `+
		`mkdir -p "$(dirname "$f")" && %s-save > "$f.conn3x" && chmod 0600 "$f.conn3x" && mv -f "$f.conn3x" "$f"`,
		plugin, deb, init, rh, r.binary())
}
