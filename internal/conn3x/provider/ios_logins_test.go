// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/ios"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
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
