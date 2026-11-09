// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

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

// hasWinPackage: Windows lists the product code as installed. The .msi
// it came from isn't checked, so source, url and sha256 are what a later
// reinstall would use.
func hasWinPackage(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	return windows.PackageInstalled(ctx, h.client, v.GetAttr("product_code").AsString())
}

func hasWinGroup(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	a, err := windows.ReadGroup(ctx, h.client, winGroupFrom(v))
	return a.Exists, err
}

// importFill adds to an import's state what the read leaves out but the
// step sets, so the first plan compares the host with the step.
var importFill = map[string]func(context.Context, *hostConn, cty.Value) (cty.Value, error){
	"conn3x_windows_file": fillWinFile,
}

// fillWinFile reads the file's content, which a windows_file read never
// does: without it, an adopted file plans an update that changes nothing
// but still fires its handlers. The read's hash must match what it got.
func fillWinFile(ctx context.Context, h *hostConn, v cty.Value) (cty.Value, error) {
	path := v.GetAttr("path").AsString()
	content, err := windows.ReadFileContent(ctx, h.client, path)
	if err != nil {
		return cty.NilVal, err
	}
	if sum := v.GetAttr("sha256"); known(sum) && sum.AsString() != digest(content) {
		return cty.NilVal, fmt.Errorf("%s changed while it was being imported; plan again", path)
	}
	vals := v.AsValueMap()
	vals["content"] = cty.StringVal(content)
	return cty.ObjectVal(vals), nil
}
