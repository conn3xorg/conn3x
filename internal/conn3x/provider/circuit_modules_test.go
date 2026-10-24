// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/opentofu/opentofu/internal/configs"
)

// Every resource type the provider serves must be usable as a circuit step,
// except the action that handlers lower to.
func TestEveryResourceTypeIsAStepModule(t *testing.T) {
	steps := map[string]bool{}
	for _, rt := range configs.Conn3xStepResourceTypes() {
		steps[rt] = true
	}
	for _, rt := range ResourceTypeNames() {
		if rt == "conn3x_service_action" {
			continue
		}
		if !steps[rt] {
			t.Errorf("%s has no step module name in configs.circuitModules", rt)
		}
	}
}
