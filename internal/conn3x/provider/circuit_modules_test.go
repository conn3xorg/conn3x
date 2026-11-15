// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/opentofu/opentofu/internal/configs"
)

// Every resource type the provider serves must be usable as a circuit step,
// except the action that handlers lower to, the commit circuits add, and
// conn3x_test_container, which a test's setup module makes, not a host.
func TestEveryResourceTypeIsAStepModule(t *testing.T) {
	steps := map[string]bool{}
	for _, rt := range configs.Conn3xStepResourceTypes() {
		steps[rt] = true
	}
	for _, rt := range ResourceTypeNames() {
		if rt == "conn3x_service_action" || rt == "conn3x_eos_commit" || rt == "conn3x_eos_removals" || rt == "conn3x_junos_commit" || rt == "conn3x_junos_removals" || rt == "conn3x_vyos_commit" || rt == "conn3x_vyos_removals" || rt == "conn3x_ios_commit" || rt == "conn3x_ios_removals" || rt == "conn3x_test_container" {
			continue
		}
		if !steps[rt] {
			t.Errorf("%s has no step module name in configs.circuitModules", rt)
		}
	}
}

// And the other way: a step module the circuits know must have a resource
// type the provider serves, or a circuit using it fails at plan with
// "does not support resource type" (conn3x_partition nearly shipped so).
func TestEveryStepModuleIsAResourceType(t *testing.T) {
	served := map[string]bool{}
	for _, rt := range ResourceTypeNames() {
		served[rt] = true
	}
	for _, rt := range configs.Conn3xStepResourceTypes() {
		if !served[rt] {
			t.Errorf("%s is a step module, but the provider doesn't serve it; add it to resourceTypes in provider.go", rt)
		}
	}
}

// Circuits sort every ssh setting into ones a host object may override and
// ones only the ssh block takes; a new setting must land in one of them.
func TestCircuitsKnowEverySSHSetting(t *testing.T) {
	known := map[string]bool{}
	for _, name := range configs.Conn3xSSHSettings() {
		known[name] = true
	}
	for name := range connectionBlock().Block.Attributes {
		if !known[name] {
			t.Errorf("ssh setting %q is missing from hostOverrides or sshOnly in internal/configs", name)
		}
		delete(known, name)
	}
	for name := range known {
		t.Errorf("internal/configs lists %q, which the ssh block doesn't have", name)
	}
}
