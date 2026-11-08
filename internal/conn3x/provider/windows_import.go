// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
)

// The Windows reads report only whether a host matches, so a missing
// object and a different one look alike after them. These ask the host
// first, for import.

func hasWinService(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	exists, _, err := windows.ServiceInSync(ctx, h.client, winServiceFrom(v))
	return exists, err
}

// hasWinRegistry asks for the value's hash only: its data may be secret.
func hasWinRegistry(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	a, err := windows.ReadRegistry(ctx, h.client, winRegistryFrom(v, ""), true)
	return a.Exists, err
}

// hasWinFeature: the feature is installed. Its sub-features and tools are
// what the step then manages.
func hasWinFeature(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	installed, _, err := windows.FeatureInSync(ctx, h.client, windows.Feature{Name: v.GetAttr("name").AsString()})
	return installed, err
}

func hasWinUser(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	a, err := windows.ReadUser(ctx, h.client, v.GetAttr("name").AsString())
	return a.Exists, err
}

func hasWinGroup(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	a, err := windows.ReadGroup(ctx, h.client, winGroupFrom(v))
	return a.Exists, err
}
