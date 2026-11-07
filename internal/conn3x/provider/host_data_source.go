// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/facts"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows/ps"
	"github.com/opentofu/opentofu/internal/providers"
)

func hostDataSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Facts about a host, read over SSH at plan time.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"os_family":  {Type: cty.String, Computed: true, Description: "\"redhat\" or \"debian\", or \"windows\" with allow_windows."},
			"os_id":      {Type: cty.String, Computed: true, Description: "os-release ID, such as rocky or ubuntu, or \"windows\"."},
			"os_version": {Type: cty.String, Computed: true, Description: "os-release VERSION_ID, such as 10.0 or 24.04. On Windows, the version such as 10.0.26100."},
			"arch":       {Type: cty.String, Computed: true, Description: "Machine architecture, such as x86_64 or aarch64."},
			"cpus":       {Type: cty.Number, Computed: true, Description: "Number of CPUs."},
			"memory_mb":  {Type: cty.Number, Computed: true, Description: "Total memory in MiB."},
			"ipv4":       {Type: cty.String, Computed: true, Description: "Source address of the default IPv4 route, or empty."},
			"allow_windows": {
				Type: cty.Bool, Optional: true,
				Description: "Experimental. Let this read succeed on Windows Server. Without it a Windows host is an error at plan, because a circuit written for Linux would otherwise take it for something it isn't.",
			},
			"windows": {
				Type: windowsFactsType, Computed: true,
				Description: "Experimental. On Windows, its release, build and update_revision, edition, installation_type, hostname, domain, domain_role, powershell version and whether the login is elevated. Null on Linux.",
			},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func readHostData(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	conn := req.Config.GetAttr("ssh")
	h, err := dialConnection(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	allow := req.Config.GetAttr("allow_windows")
	f, win, err := gatherFacts(ctx, h, h.client, known(allow) && allow.True())
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	vals := req.Config.AsValueMap()
	vals["id"] = cty.StringVal(hostPort(conn))
	vals["windows"] = win
	vals["os_family"], vals["os_id"], vals["os_version"] = cty.StringVal(f.Family), cty.StringVal(f.ID), cty.StringVal(f.Version)
	vals["arch"], vals["ipv4"] = cty.StringVal(f.Arch), cty.StringVal(f.IPv4)
	vals["cpus"], vals["memory_mb"] = cty.NumberIntVal(int64(f.CPUs)), cty.NumberIntVal(int64(f.MemoryMB))
	resp.State = cty.ObjectVal(vals)
	return resp
}

var windowsFactsType = cty.Object(map[string]cty.Type{
	"release": cty.String, "build": cty.String, "update_revision": cty.Number, "edition": cty.String, "installation_type": cty.String, "hostname": cty.String,
	"domain": cty.String, "domain_role": cty.Number, "powershell": cty.String, "elevated": cty.Bool,
})

// gatherFacts reads a host's facts. The POSIX script goes first, so a Linux
// host sees no new round trip; only when it fails is Windows tried, bypassing
// sudo. If that fails too, the host keeps the POSIX script's error.
//
// Refusing Windows by default is what protects circuits written for Linux,
// many of which treat anything that isn't Debian as Red Hat.
func gatherFacts(ctx context.Context, posix modules.Runner, raw ps.Runner, allowWindows bool) (facts.Facts, cty.Value, error) {
	noWindows := cty.NullVal(windowsFactsType)
	f, err := facts.Gather(ctx, posix)
	if err == nil || ctx.Err() != nil {
		return f, noWindows, err
	}
	w, winErr := windows.Gather(ctx, raw)
	if winErr != nil {
		// No result means it isn't Windows, or it can't tell. Anything else
		// came from a real Windows host, such as a client edition.
		var noResult *ps.NoResultError
		if errors.As(winErr, &noResult) {
			return f, noWindows, err
		}
		return f, noWindows, winErr
	}
	if !allowWindows {
		return f, noWindows, fmt.Errorf("%s is a Windows host, and this circuit doesn't support it. A circuit written for Windows sets allow_windows = true on its conn3x_host data source", w.Hostname)
	}
	return facts.Facts{Family: "windows", ID: "windows", Version: w.Version, Arch: w.Arch, CPUs: w.CPUs, MemoryMB: w.MemoryMB, IPv4: w.IPv4},
		cty.ObjectVal(map[string]cty.Value{
			"release": cty.StringVal(w.Release), "build": cty.StringVal(w.Build), "update_revision": cty.NumberIntVal(int64(w.UBR)), "edition": cty.StringVal(w.Edition), "installation_type": cty.StringVal(w.InstallationType),
			"hostname": cty.StringVal(w.Hostname), "domain": cty.StringVal(w.Domain), "domain_role": cty.NumberIntVal(int64(w.DomainRole)),
			"powershell": cty.StringVal(w.PowerShell), "elevated": cty.BoolVal(w.Elevated),
		}), nil
}
