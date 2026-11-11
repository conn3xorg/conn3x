// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/providers"
)

func packagesDataSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "The packages installed on a host, read over SSH at plan time, before this apply's steps run.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"packages": {Type: cty.Map(cty.String), Computed: true, Description: "Each installed package's newest version, by name, in the form the package module shows. Another architecture's package goes under libc6:i386 on Debian and Ubuntu, glibc.i686 on the Red Hat family."},
			"versions": {Type: cty.Map(cty.List(cty.String)), Computed: true, Description: "Every installed version of each package, oldest first, by the same names: several only where rpm installs them side by side, such as kernels."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

var serviceStateType = cty.Object(map[string]cty.Type{"state": cty.String, "enabled": cty.Bool, "unit_file_state": cty.String})

func servicesDataSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "The systemd services on a host, read over SSH at plan time, before this apply's steps run.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"services": {Type: cty.Map(serviceStateType), Computed: true, Description: "Each service by name, without .service: state is systemd's ActiveState, enabled whether its unit file starts it at boot, and unit_file_state systemd's own word, such as masked or static."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func readPackagesData(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	conn := req.Config.GetAttr("ssh")
	h, err := dialConnection(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	family, err := pkg.DetectFamily(ctx, h)
	if err == nil {
		var got map[string][]string
		if got, err = pkg.Inventory(ctx, h, family); err == nil {
			newest, all := map[string]cty.Value{}, map[string]cty.Value{}
			for name, vs := range got {
				newest[name] = cty.StringVal(vs[len(vs)-1])
				list := make([]cty.Value, len(vs))
				for i, v := range vs {
					list[i] = cty.StringVal(v)
				}
				all[name] = cty.ListVal(list)
			}
			vals := req.Config.AsValueMap()
			vals["id"] = cty.StringVal(hostPort(conn))
			vals["packages"], vals["versions"] = mapOrEmpty(newest, cty.String), mapOrEmpty(all, cty.List(cty.String))
			resp.State = cty.ObjectVal(vals)
		}
	}
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
	}
	return resp
}

func readServicesData(ctx context.Context, req providers.ReadDataSourceRequest) providers.ReadDataSourceResponse {
	var resp providers.ReadDataSourceResponse
	conn := req.Config.GetAttr("ssh")
	h, err := dialConnection(ctx, conn)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	got, err := service.Inventory(ctx, h)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	services := map[string]cty.Value{}
	for name, u := range got {
		services[name] = cty.ObjectVal(map[string]cty.Value{
			"state": cty.StringVal(u.State), "enabled": cty.BoolVal(u.Enabled()), "unit_file_state": cty.StringVal(u.UnitFileState),
		})
	}
	vals := req.Config.AsValueMap()
	vals["id"] = cty.StringVal(hostPort(conn))
	vals["services"] = mapOrEmpty(services, serviceStateType)
	resp.State = cty.ObjectVal(vals)
	return resp
}

func mapOrEmpty(m map[string]cty.Value, elem cty.Type) cty.Value {
	if len(m) == 0 {
		return cty.MapValEmpty(elem)
	}
	return cty.MapVal(m)
}
