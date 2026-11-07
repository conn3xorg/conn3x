// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package configs

import (
	"fmt"
	"strings"
	"testing"

	"github.com/opentofu/opentofu/internal/addrs"
)

func chainCircuitSrc(strategy string) string {
	return `
resource "terraform_data" "box" {}

circuit "web" {
  hosts = { a = "10.0.0.1", "dc/1" = "10.0.0.2" }
  ` + strategy + `
  ssh {
    user = "root"
  }
  step "one" {
    command {
      command = "true"
    }
  }
  step "items" {
    for_each   = ["x"]
    depends_on = [terraform_data.box]
    command {
      command = "true"
    }
  }
}
`
}

func TestConn3xStepHosts(t *testing.T) {
	mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": chainCircuitSrc("")})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	one := mod.ManagedResources["conn3x_command.web__one"]
	items := mod.ManagedResources["conn3x_command.web__items"]
	for _, tc := range []struct {
		r    *Resource
		key  addrs.InstanceKey
		want []string
	}{
		{one, addrs.StringKey("a"), []string{"a"}},
		{one, addrs.StringKey("dc/1"), []string{"dc/1"}},
		{items, addrs.StringKey("a/x"), []string{"a"}},
		// A host key with "/" gives every prefix; an extra one only adds a wait.
		{items, addrs.StringKey("dc/1/x"), []string{"dc", "dc/1"}},
		{one, addrs.IntKey(0), nil},
	} {
		if got := Conn3xStepHosts(tc.r, tc.key); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("Conn3xStepHosts(%s, %s) = %v, want %v", tc.r.Name, tc.key, got, tc.want)
		}
	}
	for _, tc := range []struct {
		r    *Resource
		key  addrs.InstanceKey
		host string
		want bool
	}{
		{one, addrs.StringKey("a"), "a", true},
		{one, addrs.StringKey("dc/1"), "a", false},
		{items, addrs.StringKey("dc/1/x"), "dc/1", true},
		{items, addrs.StringKey("a/x"), "dc/1", false},
		{items, addrs.IntKey(0), "a", true}, // not a circuit key: keep the edge
	} {
		if got := Conn3xStepOnHost(tc.r, tc.key, tc.host); got != tc.want {
			t.Errorf("Conn3xStepOnHost(%s, %s, %q) = %v, want %v", tc.r.Name, tc.key, tc.host, got, tc.want)
		}
	}
}

func TestConn3xHostEdge(t *testing.T) {
	for strategy, chained := range map[string]bool{`strategy = "per_host"`: true, `strategy = "lockstep"`: false, "": false} {
		mod, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": chainCircuitSrc(strategy)})
		if diags.HasErrors() {
			t.Fatal(diags.Error())
		}
		items := mod.ManagedResources["conn3x_command.web__items"]
		// depends_on is the user's terraform_data.box, then the chain.
		if len(items.DependsOn) != 2 {
			t.Fatalf("depends_on = %v", items.DependsOn)
		}
		if Conn3xHostEdge(items, items.DependsOn[0].SourceRange()) {
			t.Errorf("%q: the user's depends_on is narrowed per host", strategy)
		}
		if got := Conn3xHostEdge(items, items.DependsOn[1].SourceRange()); got != chained {
			t.Errorf("%q: chain edge narrowed = %v, want %v", strategy, got, chained)
		}
		if box := mod.ManagedResources["terraform_data.box"]; Conn3xHostEdge(box, box.DeclRange) {
			t.Errorf("%q: a resource outside a circuit is narrowed", strategy)
		}
	}
}

func TestCircuitStrategyErrors(t *testing.T) {
	for _, strategy := range []string{`"rolling"`, `var.x`, `1`} {
		_, diags := loadCircuitModule(t, map[string]string{"main.circuit.hcl": chainCircuitSrc("strategy = " + strategy)})
		if !diags.HasErrors() || !strings.Contains(diags.Error(), "Invalid circuit strategy") {
			t.Errorf("strategy = %s: got %v", strategy, diags)
		}
	}
}
