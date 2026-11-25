// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package firewall

import (
	"context"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
)

func TestFirewalldValidate(t *testing.T) {
	for _, ok := range []Firewalld{
		{Service: "http"},
		{Zone: "internal", Port: "8080/tcp"},
		{Port: "60000-61000/udp"},
		{RichRule: "rule family=ipv4 source address=10.0.0.0/8 port port=5432 protocol=tcp accept"},
		{Zone: "internal", RichRule: "  rule family=\"ipv6\" service name=\"ssh\" accept"},
		{Zone: "trusted", Source: "10.42.0.0/16"},
		{Zone: "trusted", Source: "169.254.169.1"},
		{Source: "fd00::/8"},
	} {
		if err := ok.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", ok, err)
		}
	}
	for _, bad := range []Firewalld{
		{},
		{Service: "http", Port: "80/tcp"},
		{Service: "http; reboot"},
		{Port: "80"},
		{Port: "70000/tcp"},
		{Port: "2000-1000/tcp"},
		{Port: "80/icmp"},
		{Zone: "pub lic", Service: "http"},
		{Service: "http", RichRule: "rule service name=http accept"},
		{RichRule: "family=ipv4 accept"},
		{RichRule: "rule family=ipv4 accept\nrule family=ipv6 accept"},
		{Source: "10.43.0.1/16"},
		{Source: "bad"},
		{Source: "10.0.0.0/8", Port: "22/tcp"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestFirewalldOption(t *testing.T) {
	if got := (Firewalld{Service: "http"}).option("add"); got != "--add-service='http'" {
		t.Fatalf("got %s", got)
	}
	if got := (Firewalld{Zone: "dmz", Port: "8443/tcp"}).option("query"); got != "--zone='dmz' --query-port='8443/tcp'" {
		t.Fatalf("got %s", got)
	}
	if got := (Firewalld{Zone: "trusted", Source: "10.42.0.0/16"}).option("query"); got != "--zone='trusted' --query-source='10.42.0.0/16'" {
		t.Fatalf("got %s", got)
	}
	if err := (Firewalld{Source: "10.43.0.1/16"}).Validate(); err == nil || !strings.Contains(err.Error(), "write it as 10.43.0.0/16") {
		t.Errorf("a host address with a prefix: %v", err)
	}
	// A rich rule goes in as one quoted word, quotes and all.
	if got := (Firewalld{RichRule: `rule family="ipv4" source address="10.0.0.0/8" accept`}).option("remove"); got != `--remove-rich-rule='rule family="ipv4" source address="10.0.0.0/8" accept'` {
		t.Fatalf("got %s", got)
	}
}

func TestUFWRule(t *testing.T) {
	for rule, want := range map[UFWRule]string{
		{Action: "allow", Port: "22/tcp"}:                           "allow 22/tcp",
		{Action: "limit", Port: "22"}:                               "limit 22",
		{Action: "deny", Port: "6000:6007/tcp", From: "10.0.0.0/8"}: "deny from 10.0.0.0/8 to any port 6000:6007 proto tcp",
		{Action: "allow", Port: "53", From: "192.0.2.1"}:            "allow from 192.0.2.1 to any port 53",
		// As ufw 0.36.2 prints them in "ufw show added": a profile name is
		// quoted only when it has a space.
		{Action: "allow", App: "OpenSSH"}:                       "allow OpenSSH",
		{Action: "limit", App: "Nginx Full"}:                    "limit 'Nginx Full'",
		{Action: "allow", App: "OpenSSH", From: "10.0.0.0/8"}:   "allow from 10.0.0.0/8 to any app OpenSSH",
		{Action: "allow", App: "Nginx Full", From: "192.0.2.1"}: "allow from 192.0.2.1 to any app 'Nginx Full'",
		{Action: "allow", App: "9p-fs_v2.0+x"}:                  "allow 9p-fs_v2.0+x",
	} {
		if err := rule.Validate(); err != nil {
			t.Errorf("rejected %+v: %v", rule, err)
			continue
		}
		if got := rule.Spec(); got != want {
			t.Errorf("Spec(%+v) = %q, want %q", rule, got, want)
		}
	}
	for _, bad := range []UFWRule{
		{Action: "permit", Port: "22"},
		{Action: "allow", Port: ""},
		{Action: "allow", Port: "6000:6007"},
		{Action: "allow", Port: "22/tcp; reboot"},
		{Action: "allow", Port: "22", From: "not-an-ip"},
		{Action: "allow", Port: "99999"},
		{Action: "allow", Port: "22/tcp", App: "OpenSSH"},
		{Action: "allow", App: "Nginx'Full"},
		{Action: "allow", App: "OpenSSH; reboot"},
		{Action: "allow", App: "$(reboot)"},
		{Action: "allow", App: " OpenSSH"},
		{Action: "allow", App: "all"},
		{Action: "allow", App: "22"},
		{Action: "allow", App: "OpenSSH", From: "not-an-ip"},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestUFWAdded(t *testing.T) {
	out := "Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\nufw deny from 10.0.0.0/8 to any port 6000:6007 proto tcp\n"
	if !ufwAdded(out, UFWRule{Action: "allow", Port: "22/tcp"}) {
		t.Error("missed an added rule")
	}
	if ufwAdded(out, UFWRule{Action: "allow", Port: "22"}) || ufwAdded(out, UFWRule{Action: "allow", Port: "2/tcp"}) {
		t.Error("matched a different rule")
	}
}

// ufwHost keeps rules the way ufw show added prints them. With lose set,
// it drops writes, as ufw does when two run at once.
type ufwHost struct {
	rules  []string
	lose   bool
	noApps bool
	ran    []string
}

func (h *ufwHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
	if strings.HasPrefix(cmd, "ufw app info ") && h.noApps {
		return ssh.Result{ExitCode: 1, Stdout: []byte("ERROR: Could not find profile 'Nginx Full'\n")}, nil
	}
	if cmd == "ufw show added" {
		return ssh.Result{Stdout: []byte("Added user rules (see 'ufw status' for running firewall):\n" + strings.Join(h.rules, "\n") + "\n")}, nil
	}
	if rule, ok := strings.CutPrefix(cmd, "flock /run/conn3x-ufw.lock ufw "); ok && !h.lose {
		h.rules = append(h.rules, "ufw "+rule)
	}
	return ssh.Result{}, nil
}

func TestApplyUFWTakesTurnsAndChecksTheRuleLanded(t *testing.T) {
	u := UFWRule{Action: "allow", Port: "80/tcp"}
	h := &ufwHost{}
	if err := ApplyUFW(context.Background(), h, u, true); err != nil {
		t.Fatal(err)
	}
	if h.ran[0] != "flock /run/conn3x-ufw.lock ufw allow 80/tcp" {
		t.Errorf("ran %q, want ufw under flock", h.ran[0])
	}

	h = &ufwHost{lose: true}
	if err := ApplyUFW(context.Background(), h, u, true); err == nil || !strings.Contains(err.Error(), "doesn't agree") {
		t.Errorf("apply = %v, want it to fail when the rule didn't land", err)
	}
}

// An app rule checks the profile is there, by its name as written, before
// ufw sees the rule.
func TestApplyUFWAppChecksTheProfile(t *testing.T) {
	u := UFWRule{Action: "allow", App: "Nginx Full"}
	h := &ufwHost{}
	if err := ApplyUFW(context.Background(), h, u, true); err != nil {
		t.Fatal(err)
	}
	if want := []string{"ufw app info 'Nginx Full'", "flock /run/conn3x-ufw.lock ufw allow 'Nginx Full'"}; len(h.ran) < 2 || h.ran[0] != want[0] || h.ran[1] != want[1] {
		t.Errorf("ran %q, want %q first", h.ran, want)
	}
	h = &ufwHost{noApps: true}
	if err := ApplyUFW(context.Background(), h, u, true); err == nil || !strings.Contains(err.Error(), `no ufw application profile "Nginx Full"`) || len(h.ran) != 1 {
		t.Errorf("apply = %v after %q, want it to stop at app info", err, h.ran)
	}
}

func TestUndo(t *testing.T) {
	u := UFWRule{Action: "deny", Port: "22/tcp"}
	if got, _ := u.Undo(true, [2]string{}); got != "flock /run/conn3x-ufw.lock ufw delete deny 22/tcp" {
		t.Errorf("ufw undo of an add: %q", got)
	}
	rules := [2]string{"### tuple ### deny tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", ""}
	want, _ := u.restore(rules)
	if got, _ := u.Undo(false, rules); got != want {
		t.Errorf("ufw undo of a delete: %q", got)
	}
	// The rule goes into a command line unquoted, so a rule nobody
	// validated never becomes one.
	for _, present := range []bool{true, false} {
		if got, err := (UFWRule{Action: "allow", Port: "80/tcp; reboot"}).Undo(present, rules); err == nil {
			t.Errorf("an invalid rule became %q", got)
		}
	}
	f := Firewalld{Zone: "public", Service: "ssh"}
	if got := strings.Join(f.Undo(true, true, false), "; "); got != "firewall-cmd --permanent --zone='public' --remove-service='ssh'" {
		t.Errorf("an add that only changed the permanent layer: %q", got)
	}
	if got := strings.Join(f.Undo(false, true, true), "; "); got != "firewall-cmd --zone='public' --add-service='ssh'; firewall-cmd --permanent --zone='public' --add-service='ssh'" {
		t.Errorf("a remove of both layers: %q", got)
	}
	if got := f.Undo(true, true, true); len(got) != 0 {
		t.Errorf("an add that changed nothing: %q", got)
	}
}

func TestNFTable(t *testing.T) {
	tb := NFTable{Family: "inet", Name: "conn3x", Content: "chain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport 22 accept\n}\n"}
	if err := tb.Validate(); err != nil {
		t.Fatal(err)
	}
	want := "table inet conn3x\ndelete table inet conn3x\ntable inet conn3x {\nchain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport 22 accept\n}\n}\n"
	if got := tb.Script(); got != want {
		t.Errorf("script:\n%s", got)
	}
	for _, bad := range []NFTable{
		{Family: "inet6", Name: "x", Content: "chain c {}"},
		{Family: "inet", Name: "1x", Content: "chain c {}"},
		{Family: "inet", Name: "x", Content: " "},
		{Family: "inet", Name: "x", Content: "chain c {}\nflush ruleset"},
		{Family: "inet", Name: "x", Content: "table ip other { }"},
		{Family: "inet", Name: "x", Content: "include \"/etc/other.nft\""},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// A body that closes the table's own brace would run what follows outside
// it, such as flushing another table, though no line starts with a word
// nftOutside refuses.
func TestNFTableStaysInsideItsTable(t *testing.T) {
	for _, content := range []string{
		"chain c {\n}\n}\nflush table inet victim\nadd table inet y {\n",
		"chain c { } } ; add rule inet filter input drop ; add table inet y {",
		"chain c {\n",
		"chain c { comment \"open\n",
	} {
		if err := (NFTable{Family: "inet", Name: "mine", Content: content}).Validate(); err == nil {
			t.Errorf("accepted %q", content)
		}
	}
	for _, content := range []string{
		"chain input {\n  type filter hook input priority 0; policy drop;\n  tcp dport 22 accept # not } a brace\n}\n",
		"chain c {\n  tcp dport 80 accept comment \"web }\"\n}\n",
		"set ok { type ipv4_addr; elements = { 192.0.2.1, 192.0.2.2 } }\nchain c { ip saddr @ok accept }\n",
	} {
		if err := (NFTable{Family: "inet", Name: "mine", Content: content}).Validate(); err != nil {
			t.Errorf("refused %q: %v", content, err)
		}
	}
}
