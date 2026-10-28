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
}

func TestUFWRule(t *testing.T) {
	for rule, want := range map[UFWRule]string{
		{Action: "allow", Port: "22/tcp"}:                           "allow 22/tcp",
		{Action: "limit", Port: "22"}:                               "limit 22",
		{Action: "deny", Port: "6000:6007/tcp", From: "10.0.0.0/8"}: "deny from 10.0.0.0/8 to any port 6000:6007 proto tcp",
		{Action: "allow", Port: "53", From: "192.0.2.1"}:            "allow from 192.0.2.1 to any port 53",
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
	rules []string
	lose  bool
	ran   []string
}

func (h *ufwHost) Run(_ context.Context, cmd string, _ []byte) (ssh.Result, error) {
	h.ran = append(h.ran, cmd)
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
