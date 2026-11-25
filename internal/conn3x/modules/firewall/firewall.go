// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package firewall opens and closes ports with firewalld, ufw or iptables.
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

// Firewalld is one service, port or rich rule in a firewalld zone, both in
// the running firewall and in its permanent configuration.
type Firewalld struct {
	Zone     string // empty means firewalld's default zone
	Service  string
	Port     string // such as 8080/tcp or 60000-61000/udp
	RichRule string // such as rule family=ipv4 source address=10.0.0.0/8 accept
	Source   string // an address or network bound to the zone, such as 10.42.0.0/16
}

var firewalldPort = regexp.MustCompile(`^(\d+)(?:-(\d+))?/(tcp|udp|sctp|dccp)$`)

// Validate checks a rule before anything reaches the host.
func (f Firewalld) Validate() error {
	if f.Zone != "" && !word.MatchString(f.Zone) {
		return fmt.Errorf("zone %q is not a firewalld zone name", f.Zone)
	}
	set := 0
	for _, v := range []string{f.Service, f.Port, f.RichRule, f.Source} {
		if v != "" {
			set++
		}
	}
	switch {
	case set != 1:
		return errors.New("set exactly one of service, port, rich_rule or source")
	case f.Source != "":
		return validSource(f.Source)
	case f.RichRule != "" && !strings.HasPrefix(strings.TrimSpace(f.RichRule), "rule "):
		return fmt.Errorf("rich_rule %q must start with rule, as firewalld's rich language does", f.RichRule)
	case strings.ContainsAny(f.RichRule, "\x00\r\n"):
		return errors.New("rich_rule has a line break or NUL")
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
	switch {
	case f.Port != "":
		opt = fmt.Sprintf("--%s-port=%s", verb, ssh.Quote(f.Port))
	case f.Source != "":
		opt = fmt.Sprintf("--%s-source=%s", verb, ssh.Quote(f.Source))
	case f.RichRule != "":
		// firewalld normalises a rich rule's text, and --query-rich-rule
		// matches it however it's spelled, so it's compared by query.
		opt = fmt.Sprintf("--%s-rich-rule=%s", verb, ssh.Quote(f.RichRule))
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
	if present && f.Source != "" {
		if err := sourceFree(ctx, r, f); err != nil {
			return err
		}
	}
	o := f.option(verb)
	res, err := r.Run(ctx, fmt.Sprintf("%s\nfirewall-cmd %s >/dev/null && firewall-cmd --permanent %s >/dev/null", firewalldRunning, o, o), nil)
	return check(res, err)
}

// validSource takes an address, or a network written as its own address,
// as firewalld keeps a source as given: 10.43.0.1/16 would be stored as
// that, and --query-source=10.43.0.0/16 would say no.
func validSource(s string) error {
	if net.ParseIP(s) != nil {
		return nil
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("source %q is not an address or CIDR", s)
	}
	if !ip.Equal(n.IP) {
		return fmt.Errorf("source %q isn't the network's own address; write it as %s", s, n)
	}
	return nil
}

// sourceFree fails when the source is bound to another zone, running or
// permanent: a source belongs to one zone, firewalld refuses a second with
// a ZONE_CONFLICT that doesn't say which, and moving it is the author's
// call to make, not the step's.
func sourceFree(ctx context.Context, r modules.Runner, f Firewalld) error {
	src := ssh.Quote(f.Source)
	zone := "$(firewall-cmd --get-default-zone)"
	if f.Zone != "" {
		zone = ssh.Quote(f.Zone)
	}
	res, err := r.Run(ctx, fmt.Sprintf(`%s
want=%s
for p in '' --permanent; do
  z=$(firewall-cmd $p --get-zone-of-source=%s 2>/dev/null) || continue
  [ "$z" = "$want" ] || { echo "$z"; exit 0; }
done`, firewalldRunning, zone, src), nil)
	if err := check(res, err); err != nil {
		return err
	}
	if other := strings.TrimSpace(string(res.Stdout)); other != "" {
		return fmt.Errorf("source %s is already bound to zone %s, and firewalld puts a source in one zone only; remove it there first, such as with firewall-cmd --zone=%s --remove-source=%s and --permanent", f.Source, other, other, f.Source)
	}
	return nil
}

// Undo is what takes back ApplyFirewalld(f, present), given whether the
// running and permanent firewall had the rule before: only the layers that
// change are put back.
func (f Firewalld) Undo(present, hadRuntime, hadPermanent bool) []string {
	verb := "add"
	if present {
		verb = "remove"
	}
	o := f.option(verb)
	var cmds []string
	if hadRuntime != present {
		cmds = append(cmds, "firewall-cmd "+o)
	}
	if hadPermanent != present {
		cmds = append(cmds, "firewall-cmd --permanent "+o)
	}
	return cmds
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
// it is safe to pass unquoted. ufw rewrites its rule files without a lock
// of its own, so two rules applied at once on one host can lose one, as a
// step with for_each does. flock makes them take turns, and the rule is
// read back so a lost write fails the step.
func ApplyUFW(ctx context.Context, r modules.Runner, u UFWRule, present bool) error {
	cmd, err := u.command(present)
	if err != nil {
		return err
	}
	res, err := r.Run(ctx, cmd, nil)
	if err := check(res, err); err != nil {
		return err
	}
	added, err := ReadUFW(ctx, r, u)
	if err != nil {
		return err
	}
	if added != present {
		return fmt.Errorf("ufw %s ran, but ufw show added doesn't agree", u.Spec())
	}
	return nil
}

// command is the ufw command line. Spec goes into it unquoted, so the rule
// is validated here, whoever the caller is.
func (u UFWRule) command(present bool) (string, error) {
	if err := u.Validate(); err != nil {
		return "", err
	}
	if present {
		return "flock /run/conn3x-ufw.lock ufw " + u.Spec(), nil
	}
	return "flock /run/conn3x-ufw.lock ufw delete " + u.Spec(), nil
}

// Undo is what takes back ApplyUFW(u, present). rules is ufw's rules as
// ListUFW read them just before a delete, so the undo puts the rule back
// where it was.
func (u UFWRule) Undo(present bool, rules [2]string) (string, error) {
	if present {
		return u.command(false)
	}
	return u.restore(rules)
}

// ufwFiles are where ufw keeps its rules, IPv4 then IPv6, one "### tuple"
// line per rule, in the order the firewall checks them.
var ufwFiles = [2]string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"}

// ListUFW is ufw's rules as the tuple lines of its two rules files, IPv4
// then IPv6, for Undo.
func ListUFW(ctx context.Context, r modules.Runner) ([2]string, error) {
	var rules [2]string
	for i, f := range ufwFiles {
		res, err := r.Run(ctx, "cat "+f, nil)
		if err := check(res, err); err != nil {
			return rules, fmt.Errorf("ufw: %s: %w", f, err)
		}
		rules[i] = ufwTuples(string(res.Stdout))
	}
	return rules, nil
}

func ufwTuples(file string) string {
	var lines []string
	for _, line := range strings.Split(file, "\n") {
		if strings.HasPrefix(line, "### tuple") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// restore puts a deleted rule back at its old place in each address
// family. A rule with no from is two ufw rules, one per family, and
// "ufw insert" of the pair can't place both, so each half goes back on its
// own, as from 0.0.0.0/0 or from ::/0, which ufw stores exactly as the
// halves of the pair. The place is the first tuple line where the file as
// listed before the delete and as it is now differ, or the end; a family
// whose file didn't change is left alone, so a delete that never happened
// isn't undone into a second copy. ufw numbers the IPv4 rules first, so an
// IPv6 rule's number is its place plus the IPv4 rule count.
func (u UFWRule) restore(rules [2]string) (string, error) {
	if err := u.Validate(); err != nil {
		return "", err
	}
	const lock = "flock /run/conn3x-ufw.lock ufw "
	// The old listing reaches awk on stdin, from a heredoc in revert.sh, and
	// ends at a marker line: an environment string or argument is capped at
	// 128 KiB, which a blocklist of a few thousand rules passes.
	// ufw numbers rules, not tuple lines: an application-profile rule is one
	// tuple per protocol ("allow Multi" with 80,443/tcp|8080/udp is two), so
	// consecutive tuples of one profile rule count once. A profile tuple has
	// the direction in field 12 (fields 10 and 11 are the profile names); a
	// plain rule's is field 10, with an optional comment= after it.
	const ufwRuleNumber = `function key(l, f, m) { m = split(l, f, " "); return (m >= 12 && f[12] ~ /^(in|out|fwd)$/) ? f[4] " " f[7] " " f[9] " " f[10] " " f[11] " " f[12] " " f[13] : "" } function num(l, k) { k = key(l); if (k == "" || k != pk) r++; pk = k; return r } `
	// Old tuples go in a[], with their rule numbers in rn[]. The first
	// current tuple that differs is where the deleted rule sat, and its rule
	// number is the place to insert it. A current file that only grew prints
	// nothing, so nothing is put back.
	const place = `awk '` + ufwRuleNumber + `s == 0 { if ($0 == "### conn3x end") s = 1; else if ($0 != "") { a[++n] = $0; rn[n] = num($0) }; next } /^### tuple/ { c++; if ($0 != a[c]) { if (c <= n) print rn[c]; f = 1; exit } } END { if (!f && c < n) print "end" }' - `
	cmds := make([]string, 2)
	for i, anywhere := range []string{"0.0.0.0/0", "::/0"} {
		half := u
		if half.From == "" {
			half.From = anywhere
		}
		base := "0"
		if i == 1 {
			base = `$(awk '` + ufwRuleNumber + `/^### tuple/ { num($0) } END { print r + 0 }' ` + ssh.Quote(ufwFiles[0]) + ")"
		}
		cmds[i] = fmt.Sprintf("p=$(%s%s <<'CONN3X_UFW_RULES'\n%s\n### conn3x end\nCONN3X_UFW_RULES\n) && case $p in '') ;; end) %s%s ;; *) %sinsert $((%s + p)) %s ;; esac",
			place, ssh.Quote(ufwFiles[i]), rules[i], lock, half.Spec(), lock, base, half.Spec())
	}
	return strings.Join(cmds, " && "), nil
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
