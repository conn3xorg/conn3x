// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
)

// The hash is the same for one account every time, so a refresh can
// compare it, and differs for another user or host with the same password.
func TestUserSecret(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	a := userSecret(key, passwordID("user", "web1", "app"), "s3cret")
	if !strings.HasPrefix(a, "$6$") {
		t.Fatalf("hash %q isn't $6$", a)
	}
	if again := userSecret(key, passwordID("user", "web1", "app"), "s3cret"); again != a {
		t.Errorf("same account, same password, another hash: %q, %q", a, again)
	}
	for _, id := range []string{passwordID("user", "web2", "app"), passwordID("user", "web1", "ops")} {
		if userSecret(key, id, "s3cret") == a {
			t.Errorf("%s got the same hash as web1/app", id)
		}
	}
	if strings.Contains(userSecretHMAC(key, "id", a), "s3cret") {
		t.Error("the HMAC holds the password")
	}
}

func TestValidateUserPassword(t *testing.T) {
	cfg := func(user string, become cty.Value, extra map[string]cty.Value) cty.Value {
		vals := map[string]cty.Value{
			"password_wo":        cty.StringVal("s3cret"),
			"password_on_create": cty.NullVal(cty.Bool),
			"password_hash_wo":   cty.NullVal(cty.String),
			"ssh":                cty.ObjectVal(map[string]cty.Value{"user": cty.StringVal(user), "become": become}),
		}
		for k, v := range extra {
			vals[k] = v
		}
		return cty.ObjectVal(vals)
	}
	for name, tc := range map[string]struct {
		cfg cty.Value
		ok  bool
	}{
		"root":                      {cfg("root", cty.NullVal(cty.Bool), nil), true},
		"become":                    {cfg("deploy", cty.True, nil), true},
		"neither":                   {cfg("deploy", cty.False, nil), false},
		"user from ssh_config_file": {cty.ObjectVal(map[string]cty.Value{"password_wo": cty.StringVal("s3cret"), "password_on_create": cty.NullVal(cty.Bool), "password_hash_wo": cty.NullVal(cty.String), "ssh": cty.ObjectVal(map[string]cty.Value{"user": cty.NullVal(cty.String), "become": cty.NullVal(cty.Bool)})}), true},
		"no password":               {cfg("deploy", cty.False, map[string]cty.Value{"password_wo": cty.NullVal(cty.String)}), true},
		"on_create, no password":    {cfg("root", cty.NullVal(cty.Bool), map[string]cty.Value{"password_wo": cty.NullVal(cty.String), "password_on_create": cty.True}), false},
	} {
		if err := validateUserPassword(tc.cfg); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLocked(t *testing.T) {
	for in, want := range map[string]struct {
		hash   string
		locked bool
	}{
		"!$6$s$h": {"$6$s$h", true},
		"$6$s$h":  {"$6$s$h", false},
		"!":       {"!", false},
		"!!":      {"!!", false},
		"*":       {"*", false},
	} {
		if h, l := account.Locked(in); h != want.hash || l != want.locked {
			t.Errorf("Locked(%q) = %q, %v", in, h, l)
		}
	}
}
