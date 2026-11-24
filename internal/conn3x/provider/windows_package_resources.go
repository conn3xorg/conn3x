// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const defaultPackageTimeout = 30 * time.Minute

func winPackageSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An MSI package on a Windows host, found by its product code. It never reboots: reboot_required says whether Windows wants one, and windows_reboot with only_if_pending does it.",
		Attributes: map[string]*configschema.Attribute{
			"id":              {Type: cty.String, Computed: true},
			"revision":        revisionAttr(),
			"product_code":    {Type: cty.String, Required: true, Description: "The MSI's ProductCode, a GUID in braces. Windows lists the package under it once installed."},
			"state":           {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
			"source":          {Type: cty.String, Optional: true, Description: "Path of the .msi already on the host. Set this or url."},
			"url":             {Type: cty.String, Optional: true, Description: "http or https address the host downloads the .msi from. Set this or source."},
			"sha256":          {Type: cty.String, Optional: true, Description: "SHA-256 of the .msi. Required with source or url: nothing installs unless the file matches."},
			"properties":      {Type: cty.Map(cty.String), Optional: true, Description: "Public MSI properties, such as INSTALLDIR. They're on msiexec's command line and in state: never secrets."},
			"allow_http":      {Type: cty.Bool, Optional: true, Description: "Let url be, or redirect to, plain http. sha256 still has to match. Off by default."},
			"max_size_mb":     {Type: cty.Number, Optional: true, Description: "Largest download, in MiB. Defaults to 2048."},
			"timeout":         {Type: cty.String, Optional: true, Description: "How long to allow. Defaults to \"30m\"."},
			"reboot_required": {Type: cty.Bool, Computed: true, Description: "Whether msiexec asked for a reboot (3010 or 1641) at the last change."},
			"in_sync":         {Type: cty.Bool, Computed: true, Description: "Whether the package matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winPackageFrom(v cty.Value) windows.Package {
	p := windows.Package{
		ProductCode: stringOr(v.GetAttr("product_code"), ""), Absent: isAbsent(v),
		Source: stringOr(v.GetAttr("source"), ""), URL: stringOr(v.GetAttr("url"), ""), SHA256: stringOr(v.GetAttr("sha256"), ""),
	}
	if props := v.GetAttr("properties"); known(props) {
		p.Properties = stringMap(props)
	}
	if a := v.GetAttr("allow_http"); known(a) {
		p.AllowHTTP = a.True()
	}
	if m := v.GetAttr("max_size_mb"); known(m) {
		n, _ := m.AsBigFloat().Int64()
		p.MaxSizeMB = int(n)
	}
	return p
}

func validateWinPackage(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateState(cfg, "source", "url", "sha256", "properties", "allow_http", "max_size_mb"))
	if t := cfg.GetAttr("timeout"); t.IsKnown() {
		if _, err := durationOr(t, defaultPackageTimeout); err != nil {
			diags = diags.Append(attrError("timeout", err.Error()))
		}
	}
	for _, a := range []string{"product_code", "state", "source", "url", "sha256", "properties", "allow_http", "max_size_mb"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := winPackageFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("product_code", err.Error()))
	}
	return diags
}

func planWinPackage(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSyncedFold(req, "windows_package", []string{"product_code"}, []string{"state", "source", "url", "sha256", "properties"})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	if vals["in_sync"].IsKnown() {
		vals["reboot_required"] = req.PriorState.GetAttr("reboot_required")
	} else {
		vals["reboot_required"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readWinPackage(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	p := winPackageFrom(req.PriorState)
	installed, err := windows.PackageInstalled(ctx, h.raw(), p.ProductCode)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, installed != p.Absent)
	return resp
}

func applyWinPackage(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_package: %w", err))
		return resp
	}
	p := winPackageFrom(req.PlannedState)
	if err := p.Validate(); err != nil {
		return fail(err)
	}
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultPackageTimeout)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	// Windows Installer runs one installation at a time.
	defer lockHost(h, "windows_package")()
	installed, err := windows.PackageInstalled(ctx, h.raw(), p.ProductCode)
	if err != nil {
		return fail(err)
	}
	restart := false
	if installed == p.Absent {
		if restart, err = windows.ApplyPackage(ctx, h.raw(), p, timeout); err != nil {
			return fail(fmt.Errorf("%s: %w", p.ProductCode, err))
		}
		if installed, err = windows.PackageInstalled(ctx, h.raw(), p.ProductCode); err != nil {
			return fail(err)
		}
		if installed == p.Absent {
			if p.Absent {
				return fail(fmt.Errorf("%s is still listed as installed after msiexec removed it", p.ProductCode))
			}
			return fail(fmt.Errorf("msiexec succeeded, but no package with product code %s is installed; check product_code against the .msi", p.ProductCode))
		}
	}
	vals := withSync(req.PlannedState, true).AsValueMap()
	vals["reboot_required"] = cty.BoolVal(restart)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

const defaultDownloadTimeout = 30 * time.Minute

func winDownloadSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A file downloaded to a Windows host, kept only when it has the configured SHA-256. It's written beside dest and renamed into place, never following a link.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"revision":    revisionAttr(),
			"url":         {Type: cty.String, Required: true, Description: "https address to download from, or http with allow_http. Redirects are followed, up to five, and none may drop to http unless allow_http is set."},
			"dest":        {Type: cty.String, Required: true, Description: "Full path to save it to, such as C:\\Tools\\tool.zip. Its folder has to exist."},
			"sha256":      {Type: cty.String, Required: true, Description: "The file's SHA-256, as 64 hex characters. A download with another one is refused, and dest is left as it was."},
			"allow_http":  {Type: cty.Bool, Optional: true, Description: "Allow url, or a redirect, to use plain http. sha256 still has to match."},
			"max_size_mb": {Type: cty.Number, Optional: true, Description: "Largest download, in MiB. Defaults to 2048."},
			"timeout":     {Type: cty.String, Optional: true, Description: "How long to allow. Defaults to \"30m\"."},
			"on_remove":   {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the file, \"delete\" removes it, or a link in its place but not what it points to."},
			"in_sync":     {Type: cty.Bool, Computed: true, Description: "Whether dest was a file with the configured SHA-256 at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winDownloadFrom(v cty.Value) windows.Download {
	d := windows.Download{URL: stringOr(v.GetAttr("url"), ""), Dest: stringOr(v.GetAttr("dest"), ""), SHA256: stringOr(v.GetAttr("sha256"), "")}
	if a := v.GetAttr("allow_http"); known(a) && a.True() {
		d.AllowHTTP = true
	}
	if m := v.GetAttr("max_size_mb"); known(m) {
		n, _ := m.AsBigFloat().Int64()
		d.MaxSizeMB = int(n)
	}
	return d
}

func validateWinDownload(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if t := cfg.GetAttr("timeout"); !t.IsNull() {
		if _, err := durationOr(t, defaultDownloadTimeout); err != nil {
			diags = diags.Append(attrError("timeout", err.Error()))
		}
	}
	if err := winDownloadFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("url", err.Error()))
	}
	return diags
}

func planWinDownload(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	// A new url with the same sha256 is the same file, so it plans no
	// download if dest already has it.
	return planSynced(req, "windows_download", []string{"dest"}, []string{"url", "sha256"})
}

func readWinDownload(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	ok, err := windows.DownloadInSync(ctx, h.raw(), winDownloadFrom(req.PriorState))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_download: %w", err))
		return resp
	}
	resp.NewState = withSync(req.PriorState, ok)
	return resp
}

func applyWinDownload(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_download: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		if err := windows.ApplyFileRemove(ctx, h.raw(), winDownloadFrom(req.PriorState).Dest); err != nil {
			return fail(err)
		}
		return resp
	}
	d := winDownloadFrom(req.PlannedState)
	if err := d.Validate(); err != nil {
		return fail(err)
	}
	timeout, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultDownloadTimeout)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	ok, err := windows.DownloadInSync(ctx, h.raw(), d)
	if err != nil {
		return fail(err)
	}
	if !ok {
		if err := windows.ApplyDownload(ctx, h.raw(), d, timeout); err != nil {
			return fail(fmt.Errorf("downloading %s: %w", d.Dest, err))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}
