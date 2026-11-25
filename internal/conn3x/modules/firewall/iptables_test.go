// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package firewall

import (
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestIPTablesValidate(t *testing.T) {
	for _, good := range []IPTablesRule{
		{Chain: "INPUT", Protocol: "tcp", DestinationPort: "22", Jump: "ACCEPT"},
		{Table: "filter", Chain: "INPUT", Protocol: "tcp", DestinationPorts: []string{"80", "443", "8000:8010"}, Source: "10.0.0.0/8", Jump: "ACCEPT"},
		{Chain: "FORWARD", InInterface: "eth0", OutInterface: "wg+", CTState: []string{"ESTABLISHED", "RELATED"}, Jump: "ACCEPT"},
		{Chain: "INPUT", Source: "2001:db8::/32", IPv6: true, Jump: "DROP", Insert: true, RuleNum: 2},
		{Table: "nat", Chain: "POSTROUTING", OutInterface: "eth0", Jump: "MASQUERADE", Comment: "it's \"nat\" $HOME"},
		{Chain: "INPUT", InInterface: "abcdefghijklmno"},
		{Chain: "INPUT", InInterface: "abcdefghijklmn+"},
	} {
		if err := good.Validate(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
	for _, bad := range []IPTablesRule{
		{Chain: "", Jump: "ACCEPT"},
		{Chain: "INPUT; reboot", Jump: "ACCEPT"},
		{Table: "broute", Chain: "INPUT"},
		{Chain: "INPUT", DestinationPort: "22"},
		{Chain: "INPUT", Protocol: "icmp", DestinationPort: "22"},
		{Chain: "INPUT", Protocol: "tcp", DestinationPort: "99999"},
		{Chain: "INPUT", Protocol: "tcp", DestinationPort: "22", DestinationPorts: []string{"80"}},
		{Chain: "INPUT", Protocol: "tcp", DestinationPorts: strings.Split("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16", ",")},
		{Chain: "INPUT", Source: "example.com"},
		{Chain: "INPUT", Source: "10.0.0.1,10.0.0.2"},
		{Chain: "INPUT", Source: "2001:db8::1"},
		{Chain: "INPUT", Destination: "10.0.0.1", IPv6: true},
		{Chain: "INPUT", InInterface: "eth0 lo"},
		{Chain: "INPUT", InInterface: "abcdefghijklmno+"},
		{Chain: "INPUT", OutInterface: "abcdefghijklmnop"},
		{Chain: "INPUT", CTState: []string{"new"}},
		{Chain: "INPUT", Jump: "ACCEPT --reject-with x"},
		{Chain: "INPUT", Comment: "two\nlines"},
		{Chain: "INPUT", RuleNum: 3},
		{Chain: "INPUT", Insert: true, RuleNum: -1},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// -C, -A, -I and -D carry the same spec, every word quoted, so a comment
// with quotes and $ reaches iptables as one argument.
func TestIPTablesCommands(t *testing.T) {
	r := IPTablesRule{Chain: "INPUT", Protocol: "tcp", Source: "10.0.0.0/8", DestinationPorts: []string{"80", "443"}, InInterface: "eth0",
		CTState: []string{"NEW"}, Comment: `it's "web" $HOME`, Jump: "ACCEPT"}
	spec := `'-p' 'tcp' '-s' '10.0.0.0/8' '-i' 'eth0' '-m' 'multiport' '--dports' '80,443' '-m' 'conntrack' '--ctstate' 'NEW' '-m' 'comment' '--comment' 'it'\''s "web" $HOME' '-j' 'ACCEPT'`
	for op, want := range map[string]string{
		"-C": `'iptables' '-w' '-t' 'filter' '-C' 'INPUT' ` + spec,
		"-A": `'iptables' '-w' '-t' 'filter' '-A' 'INPUT' ` + spec,
		"-I": `'iptables' '-w' '-t' 'filter' '-I' 'INPUT' ` + spec,
		"-D": `'iptables' '-w' '-t' 'filter' '-D' 'INPUT' ` + spec,
	} {
		if got := r.command(op); got != want {
			t.Errorf("%s:\ngot  %s\nwant %s", op, got, want)
		}
	}
	r = IPTablesRule{Table: "raw", Chain: "PREROUTING", Protocol: "udp", SourcePort: "53", DestinationPort: "1024:65535", IPv6: true, Insert: true, RuleNum: 3, Jump: "NOTRACK"}
	if got, want := r.change(true), `'ip6tables' '-w' '-t' 'raw' '-I' 'PREROUTING' '3' '-p' 'udp' '--sport' '53' '--dport' '1024:65535' '-j' 'NOTRACK'`; got != want {
		t.Errorf("insert:\ngot  %s\nwant %s", got, want)
	}
	if got := r.change(false); !strings.Contains(got, `'-D' 'PREROUTING' '-p'`) {
		t.Errorf("delete names no rule number: %s", got)
	}
}

// iptHost answers -C with has, and records every other command.
type iptHost struct {
	has  bool
	code int // the exit status for -C when not 0 or 1
	ran  []string
}

func (h *iptHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	if strings.Contains(cmd, "'-C'") {
		switch {
		case h.code != 0:
			return ssh.Result{ExitCode: h.code, Stderr: []byte("iptables v1.8.10: unknown option")}, nil
		case h.has:
			return ssh.Result{}, nil
		}
		return ssh.Result{ExitCode: 1, Stderr: []byte("iptables: Bad rule (does a matching rule exist in that chain?).")}, nil
	}
	h.ran = append(h.ran, cmd)
	return ssh.Result{}, nil
}

func TestApplyIPTables(t *testing.T) {
	r := IPTablesRule{Chain: "INPUT", Protocol: "tcp", DestinationPort: "22", Jump: "ACCEPT"}
	for _, c := range []struct {
		has, present, persist bool
		want                  []string
	}{
		{false, true, false, []string{r.command("-A")}},
		{true, true, false, nil},
		{true, false, false, []string{r.command("-D")}},
		{false, false, false, nil},
		{false, true, true, []string{r.command("-A"), r.SaveCommand()}},
		{true, true, true, []string{r.SaveCommand()}},
		{true, false, true, []string{r.command("-D"), r.SaveCommand()}},
	} {
		h := &iptHost{has: c.has}
		r.Persist = c.persist
		if err := ApplyIPTables(context.Background(), h, r, c.present); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(h.ran, c.want) {
			t.Errorf("has %v present %v persist %v: ran %q, want %q", c.has, c.present, c.persist, h.ran, c.want)
		}
	}
	if _, err := ReadIPTables(context.Background(), &iptHost{code: 2}, r); err == nil || !strings.Contains(err.Error(), "unknown option") {
		t.Errorf("exit 2: %v", err)
	}
	// iptables 1.8.11 says "Bad rule" for an absent rule and a missing
	// chain alike, so both read as missing; any other exit 1 or 2 is an error.
	for out, want := range map[string]string{
		"iptables: Bad rule (does a matching rule exist in that chain?).": "",
		"iptables: Resource temporarily unavailable.":                     "Resource temporarily unavailable",
	} {
		has, err := ReadIPTables(context.Background(), runFunc(func(string) ssh.Result {
			return ssh.Result{ExitCode: 1, Stderr: []byte(out)}
		}), r)
		if want == "" && (has || err != nil) || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("exit 1 %q: has %v, err %v", out, has, err)
		}
	}
	if _, err := ReadIPTables(context.Background(), runFunc(func(string) ssh.Result {
		return ssh.Result{ExitCode: 2, Stderr: []byte("iptables v1.8.11 (nf_tables): Couldn't load target `NOPE'")}
	}), r); err == nil || !strings.Contains(err.Error(), "Couldn't load target") {
		t.Errorf("exit 2: %v", err)
	}
	if _, err := ReadIPTables(context.Background(), &iptHost{code: 127}, r); err == nil || !strings.Contains(err.Error(), "install the iptables package") {
		t.Errorf("exit 127: %v", err)
	}
}

func TestIPTablesUndo(t *testing.T) {
	r := IPTablesRule{Chain: "INPUT", Protocol: "tcp", DestinationPort: "22", Jump: "ACCEPT"}
	if got := r.Undo(true, false, ""); !reflect.DeepEqual(got, []string{r.command("-D")}) {
		t.Errorf("undo of an add: %q", got)
	}
	if got := r.Undo(false, true, "-P INPUT ACCEPT\n"); !reflect.DeepEqual(got, []string{r.restore("-P INPUT ACCEPT\n")}) {
		t.Errorf("undo of a delete: %q", got)
	}
	if got := r.Undo(true, true, ""); got != nil {
		t.Errorf("undo of nothing: %q", got)
	}
	r.Persist = true
	for _, present := range []bool{true, false} {
		if got := r.Undo(present, !present, ""); len(got) != 2 || got[1] != r.SaveCommand() {
			t.Errorf("undo with persist, present %v: %q", present, got)
		}
	}
}

// The undo of a delete runs against a stand-in iptables that lists the
// chain as it is after the delete, and reports where it would insert.
func TestIPTablesRestorePosition(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	const (
		replies = "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
		sshRule = `-A INPUT -p tcp -m tcp --dport 22 -m comment --comment "it\'s \"ssh\" $HOME" -j ACCEPT` + "\n"
		drop    = "-A INPUT -j DROP\n"
	)
	for _, c := range []struct {
		name          string
		rule          IPTablesRule
		before, after string
		has           bool
		want          string
	}{
		{"appended above a drop", IPTablesRule{Chain: "INPUT", Jump: "ACCEPT"}, "-P INPUT ACCEPT\n" + replies + sshRule + drop, "-P INPUT ACCEPT\n" + replies + drop, false, "-I INPUT 2"},
		{"inserted at the top", IPTablesRule{Chain: "INPUT", Jump: "ACCEPT", Insert: true, RuleNum: 3}, "-P INPUT DROP\n" + replies + sshRule, "-P INPUT DROP\n" + sshRule, false, "-I INPUT 1"},
		{"last", IPTablesRule{Chain: "INPUT", Jump: "DROP"}, "-P INPUT ACCEPT\n" + replies + drop, "-P INPUT ACCEPT\n" + replies, false, "-I INPUT 2"},
		{"user chain, ip6tables", IPTablesRule{Chain: "web", Table: "mangle", Jump: "ACCEPT", IPv6: true}, "-N web\n" + sshRule, "-N web\n", false, "-I web 1"},
		{"never deleted", IPTablesRule{Chain: "INPUT", Jump: "ACCEPT"}, "-P INPUT ACCEPT\n" + sshRule, "-P INPUT ACCEPT\n" + sshRule, true, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			bin := c.rule.binary()
			has := "1"
			if c.has {
				has = "0"
			}
			// $1 -w, $2 -t, $3 table, $4 op, $5 chain, $6 position.
			stub := bin + `() { case "$4" in -C) return ` + has + `;; -S) printf %s "$AFTER";; -I) echo "$3 $4 $5 $6";; esac; }` + "\n"
			cmd := exec.Command("sh", "-c", stub+c.rule.restore(c.before))
			cmd.Env = append(os.Environ(), "AFTER="+c.after)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			want := ""
			if c.want != "" {
				want = c.rule.table() + " " + c.want + "\n"
			}
			if string(out) != want {
				t.Errorf("got %q, want %q", out, want)
			}
		})
	}
}

func TestIPTablesSaveCommand(t *testing.T) {
	v4 := IPTablesRule{}.SaveCommand()
	for _, w := range []string{"plugins.d/15-ip4tables ]; then f=/etc/iptables/rules.v4", "/usr/libexec/iptables/iptables.init ]; then f=/etc/sysconfig/iptables;", "iptables-save >", "iptables-persistent"} {
		if !strings.Contains(v4, w) {
			t.Errorf("v4 missing %q: %s", w, v4)
		}
	}
	v6 := IPTablesRule{IPv6: true}.SaveCommand()
	for _, w := range []string{"plugins.d/25-ip6tables ]; then f=/etc/iptables/rules.v6", "ip6tables.init ]; then f=/etc/sysconfig/ip6tables;", "ip6tables-save >"} {
		if !strings.Contains(v6, w) {
			t.Errorf("v6 missing %q: %s", w, v6)
		}
	}
}

type runFunc func(string) ssh.Result

func (f runFunc) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) { return f(cmd), nil }
