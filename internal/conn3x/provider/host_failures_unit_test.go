// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"path/filepath"
	"testing"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/providers"
)

// unitHostSteps are host steps with on_remove, each with the arguments it
// needs to plan.
var unitHostSteps = map[string]map[string]cty.Value{
	"conn3x_npm":               {"name": cty.StringVal("left-pad"), "global": cty.True},
	"conn3x_pip":               {"name": cty.StringVal("requests"), "venv": cty.StringVal("/opt/app/venv")},
	"conn3x_snap":              {"name": cty.StringVal("hello")},
	"conn3x_flatpak":           {"name": cty.StringVal("org.gnome.Calculator")},
	"conn3x_service":           {"name": cty.StringVal("nginx"), "state": cty.StringVal("started")},
	"conn3x_package":           {"name": cty.StringVal("tree")},
	"conn3x_package_hold":      {"name": cty.StringVal("tree")},
	"conn3x_timer":             {"name": cty.StringVal("cleanup"), "on_calendar": cty.StringVal("daily"), "command": cty.StringVal("true")},
	"conn3x_cron":              {"name": cty.StringVal("backup"), "schedule": cty.StringVal("@daily"), "command": cty.StringVal("true")},
	"conn3x_nm_connection":     {"name": cty.StringVal("lan"), "ifname": cty.StringVal("eth1"), "type": cty.StringVal("ethernet")},
	"conn3x_postgresql_role":   {"name": cty.StringVal("app")},
	"conn3x_mysql_user":        {"name": cty.StringVal("app")},
	"conn3x_mysql_database":    {"name": cty.StringVal("app")},
	"conn3x_container":         {"name": cty.StringVal("web"), "image": cty.StringVal("nginx:1.27")},
	"conn3x_container_image":   {"name": cty.StringVal("nginx"), "tag": cty.StringVal("1.27")},
	"conn3x_container_network": {"name": cty.StringVal("app")},
	"conn3x_container_volume":  {"name": cty.StringVal("data")},
	"conn3x_compose_project":   {"project_dir": cty.StringVal("/opt/app")},
	"conn3x_modprobe":          {"name": cty.StringVal("br_netfilter")},
	"conn3x_swap":              {"path": cty.StringVal("/swapfile"), "size": cty.StringVal("1G")},
	"conn3x_sysctl":            {"name": cty.StringVal("vm.swappiness"), "value": cty.StringVal("10")},
	"conn3x_user":              {"name": cty.StringVal("deploy")},
	"conn3x_group":             {"name": cty.StringVal("ops")},
}

// On a host whose every command fails, creating a step fails, and so does
// removing it with on_remove = "delete"; "forget" never reaches the host.
func TestHostStepsSurfaceHostFailures(t *testing.T) {
	broken := unitHost(t, (&unitScripts{}).on("", "!sh: the host broke").answer)
	away := map[string]cty.Value{"private_key_file": cty.StringVal(filepath.Join(t.TempDir(), "missing"))}
	p, _ := New()
	for typeName, attrs := range unitHostSteps {
		t.Run(typeName, func(t *testing.T) {
			cfg := eosStep(typeName, attrs, broken)
			if v := p.ValidateResourceConfig(ctx, providers.ValidateResourceConfigRequest{TypeName: typeName, Config: cfg}); v.Diagnostics.HasErrors() {
				t.Fatalf("validate: %v", v.Diagnostics.Err())
			}
			null := cty.NullVal(cfg.Type())
			plan := p.PlanResourceChange(ctx, providers.PlanResourceChangeRequest{TypeName: typeName, PriorState: null, ProposedNewState: cfg, Config: cfg})
			if plan.Diagnostics.HasErrors() {
				t.Fatalf("plan: %v", plan.Diagnostics.Err())
			}
			planned := plan.PlannedState
			if resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: null, PlannedState: planned, Config: cfg}); !resp.Diagnostics.HasErrors() {
				t.Error("created on a broken host")
			}
			prior := func(onRemove string, ssh map[string]cty.Value) cty.Value {
				vals := eosStep(typeName, attrs, ssh).AsValueMap()
				for k, v := range planned.AsValueMap() {
					if k != "ssh" && v.IsKnown() {
						vals[k] = v
					}
				}
				vals["on_remove"] = cty.StringVal(onRemove)
				return cty.ObjectVal(vals)
			}
			gone := prior(onRemoveDelete, broken)
			if resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: gone, PlannedState: null}); !resp.Diagnostics.HasErrors() {
				t.Error("deleted on a broken host")
			}
			if resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: prior(onRemoveForget, away), PlannedState: null}); resp.Diagnostics.HasErrors() {
				t.Errorf("forget reached the host: %v", resp.Diagnostics.Err())
			}
			if resp := p.ApplyResourceChange(ctx, providers.ApplyResourceChangeRequest{TypeName: typeName, PriorState: null, PlannedState: eosStep(typeName, attrs, away), Config: cfg}); !resp.Diagnostics.HasErrors() {
				t.Error("created over a login with a missing key")
			}
		})
	}
}
