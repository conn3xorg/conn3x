// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package windows

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
)

// Inventory lists what a Windows host has of a kind, by name: "features"
// (the installed ones), "services", "users" and "groups" (local accounts).
// conn3x generate steps writes import steps from it.
func Inventory(ctx context.Context, r ps.Runner, kind string) ([]string, error) {
	switch kind {
	case "features", "services", "users", "groups":
	default:
		return nil, fmt.Errorf("can't list Windows %q", kind)
	}
	res, err := ps.Read(ctx, r, script("read_inventory.ps1"), map[string]any{"kind": kind})
	if err != nil {
		return nil, err
	}
	var out struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(res.Value, &out); err != nil {
		return nil, fmt.Errorf("reading the %s list: %w", kind, err)
	}
	return out.Names, nil
}
