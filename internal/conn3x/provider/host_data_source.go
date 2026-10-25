// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/facts"
	"github.com/opentofu/opentofu/internal/providers"
)

func hostDataSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Facts about a host, read over SSH at plan time.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"os_family":  {Type: cty.String, Computed: true, Description: "\"redhat\" or \"debian\"."},
			"os_id":      {Type: cty.String, Computed: true, Description: "os-release ID, such as rocky or ubuntu."},
			"os_version": {Type: cty.String, Computed: true, Description: "os-release VERSION_ID, such as 10.0 or 24.04."},
			"arch":       {Type: cty.String, Computed: true, Description: "Machine architecture, such as x86_64 or aarch64."},
			"cpus":       {Type: cty.Number, Computed: true, Description: "Number of CPUs."},
			"memory_mb":  {Type: cty.Number, Computed: true, Description: "Total memory in MiB."},
			"ipv4":       {Type: cty.String, Computed: true, Description: "Source address of the default IPv4 route, or empty."},
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
	f, err := facts.Gather(ctx, h)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	vals := req.Config.AsValueMap()
	vals["id"] = cty.StringVal(conn.GetAttr("host").AsString())
	vals["os_family"], vals["os_id"], vals["os_version"] = cty.StringVal(f.Family), cty.StringVal(f.ID), cty.StringVal(f.Version)
	vals["arch"], vals["ipv4"] = cty.StringVal(f.Arch), cty.StringVal(f.IPv4)
	vals["cpus"], vals["memory_mb"] = cty.NumberIntVal(int64(f.CPUs)), cty.NumberIntVal(int64(f.MemoryMB))
	resp.State = cty.ObjectVal(vals)
	return resp
}
