// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/ios"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
)

// countedLogin is one fresh login: it counts how many are open at once.
type countedLogin struct {
	open, most *int32
}

func (c countedLogin) answer() (ssh.Result, error) {
	time.Sleep(5 * time.Millisecond)
	return ssh.Result{Stdout: []byte("%No Rollback Confirmed Change pending\n")}, nil
}

func (c countedLogin) RunRaw(context.Context, string, []byte) (ssh.Result, error) { return c.answer() }
func (c countedLogin) RunShell(context.Context, []byte) (ssh.Result, error)       { return c.answer() }
func (c countedLogin) Close() error                                               { atomic.AddInt32(c.open, -1); return nil }

// Eight steps refreshing at once on one IOS device open one login at a
// time, not a login each (Foothills' review of #836).
func TestOneFreshLoginPerHost(t *testing.T) {
	var open, most int32
	dial := func(context.Context) (ios.Device, error) {
		n := atomic.AddInt32(&open, 1)
		for m := atomic.LoadInt32(&most); n > m && !atomic.CompareAndSwapInt32(&most, m, n); m = atomic.LoadInt32(&most) {
		}
		return countedLogin{&open, &most}, nil
	}
	d := ios.PerCommand(oneLoginAtATime("203.0.113.20", dial))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ios.Pending(context.Background(), d); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if most != 1 || open != 0 {
		t.Errorf("at most %d logins open at once, %d left open; want 1 and 0", most, open)
	}

	// A login that fails gives the token back, and a cancelled wait gives up.
	failing := oneLoginAtATime("203.0.113.21", func(context.Context) (ios.Device, error) { return nil, context.DeadlineExceeded })
	if _, err := failing(context.Background()); err == nil {
		t.Fatal("no error")
	}
	held, err := oneLoginAtATime("203.0.113.21", dial)(context.Background())
	if err != nil {
		t.Fatalf("the failed login kept the token: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := oneLoginAtATime("203.0.113.21", dial)(ctx); err == nil {
		t.Error("a second login got in while the first was open")
	}
	_ = held.(interface{ Close() error }).Close()
}

// An IOS step's hostConn is its name and lock key, without a login: it
// logs in per command, so a pooled one would only hold a vty line (#837).
func TestIOSHostNeedsNoLogin(t *testing.T) {
	conn := objFor(iosConfigSchema(), map[string]cty.Value{"lines": cty.ListVal([]cty.Value{cty.StringVal("hostname r1")})}).GetAttr("ssh")
	h, err := iosPlatform.hostFor(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if h.client != nil || h.host != "203.0.113.10" || h.rootKey == "" {
		t.Errorf("hostConn %+v", h)
	}
}

func TestIOSHostnameValidate(t *testing.T) {
	r := resourceTypes["conn3x_ios_hostname"]
	for _, name := range []string{"123", "edge.lab", "edge-"} {
		if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal(name)})); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"name": cty.StringVal("edge01")})); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

func TestIOSInterfaceValidate(t *testing.T) {
	r := resourceTypes["conn3x_ios_interface"]
	for name, attrs := range map[string]map[string]cty.Value{
		"EOS spelling":      {"name": cty.StringVal("Port-Channel10")},
		"switchport on SVI": {"name": cty.StringVal("Vlan20"), "mode": cty.StringVal("access")},
		"bad on_remove":     {"name": cty.StringVal("GigabitEthernet1"), "on_remove": cty.StringVal("purge")},
	} {
		if diags := r.validate(objFor(r.schema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"name": cty.StringVal("GigabitEthernet1/0/1"), "mode": cty.StringVal("trunk"), "allowed_vlans": cty.ListVal([]cty.Value{cty.NumberIntVal(10), cty.NumberIntVal(20)})}
	if diags := r.validate(objFor(r.schema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

func TestIOSVLANValidate(t *testing.T) {
	r := resourceTypes["conn3x_ios_vlan"]
	for _, id := range []int64{1, 1003, 4095} {
		if diags := r.validate(objFor(r.schema(), map[string]cty.Value{"vlan_id": cty.NumberIntVal(id)})); !diags.HasErrors() {
			t.Errorf("VLAN %d: no error", id)
		}
	}
	ok := map[string]cty.Value{"vlan_id": cty.NumberIntVal(10), "name": cty.StringVal("users")}
	if diags := r.validate(objFor(r.schema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

func TestIOSStaticRouteValidate(t *testing.T) {
	r := resourceTypes["conn3x_ios_static_route"]
	hops := func(h ...string) cty.Value {
		var v []cty.Value
		for _, x := range h {
			v = append(v, cty.StringVal(x))
		}
		return cty.ListVal(v)
	}
	for name, attrs := range map[string]map[string]cty.Value{
		"host bits":    {"prefix": cty.StringVal("10.0.0.1/8"), "next_hops": hops("192.0.2.1")},
		"wrong family": {"prefix": cty.StringVal("10.0.0.0/8"), "next_hops": hops("2001:db8::1")},
		"distance":     {"prefix": cty.StringVal("10.0.0.0/8"), "next_hops": hops("192.0.2.1"), "distance": cty.NumberIntVal(256)},
	} {
		if diags := r.validate(objFor(r.schema(), attrs)); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
	ok := map[string]cty.Value{"prefix": cty.StringVal("0.0.0.0/0"), "next_hops": hops("192.0.2.1", "192.0.2.2"), "distance": cty.NumberIntVal(10)}
	if diags := r.validate(objFor(r.schema(), ok)); diags.HasErrors() {
		t.Error(diags.Err())
	}
}

// lines_wo on ios_config: the plan keeps each line's start, never the
// secret, and validate refuses what the step can't own.
func TestIOSConfigLinesWO(t *testing.T) {
	t.Setenv(hmacKeyEnv, strings.Repeat("k", 32))
	r := resourceTypes["conn3x_ios_config"]
	secret := "S3cretK3y"
	cfg := objFor(r.schema(), map[string]cty.Value{
		"lines":    cty.ListVal([]cty.Value{cty.StringVal("tacacs-server host 192.0.2.5")}),
		"lines_wo": cty.ListVal([]cty.Value{cty.StringVal("tacacs-server key " + secret), cty.StringVal("ntp authentication-key 1 md5 " + secret)}),
	})
	if diags := r.validate(cfg); diags.HasErrors() {
		t.Fatal(diags.Err())
	}
	plan := r.plan(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), Config: cfg, ProposedNewState: cfg})
	if err := plan.Diagnostics.Err(); err != nil {
		t.Fatal(err)
	}
	want := cty.ListVal([]cty.Value{cty.StringVal("tacacs-server key"), cty.StringVal("ntp authentication-key 1")})
	if p := plan.PlannedState.GetAttr("lines_wo_prefixes"); p.IsKnown() && !p.Equals(want).True() {
		t.Errorf("lines_wo_prefixes %#v", p)
	}
	if !plan.PlannedState.GetAttr("lines_wo").IsNull() || strings.Contains(fmt.Sprintf("%#v", plan.PlannedState), secret) {
		t.Errorf("the planned state holds the secret: %#v", plan.PlannedState)
	}
	for name, lines := range map[string][]string{
		"community":  {"snmp-server community public RO"},
		"no secret":  {"ntp server 192.0.2.1"},
		"same start": {"tacacs-server key A1", "tacacs-server key B2"},
	} {
		var v []cty.Value
		for _, l := range lines {
			v = append(v, cty.StringVal(l))
		}
		bad := objFor(r.schema(), map[string]cty.Value{"lines_wo": cty.ListVal(v)})
		if diags := r.validate(bad); !diags.HasErrors() {
			t.Errorf("%s: no error", name)
		}
	}
}
