// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// userOn is a planned-for user resource on 127.0.0.1 with the given SSH port
// (cty.NilVal leaves it unset).
func userOn(port cty.Value, attrs map[string]cty.Value) cty.Value {
	v := userObj(attrs).AsValueMap()
	ssh := v["ssh"].AsValueMap()
	ssh["host"] = cty.StringVal("127.0.0.1")
	if port != cty.NilVal {
		ssh["port"] = port
	}
	v["ssh"] = cty.ObjectVal(ssh)
	return cty.ObjectVal(v)
}

func TestIDsTellApartHostsOnOneAddress(t *testing.T) {
	deploy := map[string]cty.Value{"name": cty.StringVal("deploy")}
	for _, tc := range []struct {
		port cty.Value
		want string
	}{
		{cty.NilVal, "127.0.0.1:user:deploy"},
		{cty.NumberIntVal(22), "127.0.0.1:user:deploy"},
		{cty.NumberIntVal(2221), "127.0.0.1:2221:user:deploy"},
		{cty.NumberIntVal(2222), "127.0.0.1:2222:user:deploy"},
	} {
		cfg := userOn(tc.port, deploy)
		got := planUser(providers.PlanResourceChangeRequest{PriorState: cty.NullVal(cfg.Type()), ProposedNewState: cfg, Config: cfg}).PlannedState.GetAttr("id")
		if !got.RawEquals(cty.StringVal(tc.want)) {
			t.Errorf("port %#v: id %#v, want %q", tc.port, got, tc.want)
		}
	}
}

func TestIDsWrittenWithoutThePortStay(t *testing.T) {
	// State from v0.2.2 and earlier has no port in its ids; upgrading must not plan a change.
	old := map[string]cty.Value{}
	for k, v := range deployState {
		old[k] = v
	}
	old["id"] = cty.StringVal("127.0.0.1:user:deploy")
	prior := userOn(cty.NumberIntVal(2222), old)
	cfg := userOn(cty.NumberIntVal(2222), map[string]cty.Value{"name": cty.StringVal("deploy"), "shell": cty.StringVal("/bin/bash")})
	if planned := planUsr(prior, cfg); !planned.RawEquals(prior) {
		t.Fatalf("upgrade planned a change:\n%#v", planned)
	}
}
