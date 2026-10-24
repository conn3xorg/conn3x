// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/system"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func sysctlSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A kernel parameter, set now and kept across reboots in /etc/sysctl.d.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"name":      {Type: cty.String, Required: true, Description: "Key, such as net.ipv4.ip_forward."},
			"value":     {Type: cty.String, Required: true, Description: "Value. Separate several with spaces."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the setting, \"delete\" removes its file; the running value stays until reboot."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the file and the running kernel both have the value."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func sysctlFrom(v cty.Value) system.Sysctl {
	return system.Sysctl{Key: v.GetAttr("name").AsString(), Value: v.GetAttr("value").AsString()}
}

func validateSysctl(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := sysctlFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planSysctl(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "sysctl", false, []string{"value"})
}

func readSysctl(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		s := sysctlFrom(prior)
		a, err := file.Read(ctx, h, s.Path())
		if err != nil {
			return cty.NilVal, err
		}
		live, err := system.ReadSysctl(ctx, h, s.Key)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, a.Content == s.Content() && s.Matches(live)), nil
	})
}

func applySysctl(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			s := sysctlFrom(planned)
			if err := system.ApplySysctl(ctx, h, s); err != nil {
				return cty.NilVal, fmt.Errorf("sysctl %s: %w", s.Key, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			return file.Delete(ctx, h, sysctlFrom(prior).Path())
		})
}

// singletonSchema is the shape of a setting a host has exactly one of.
func singletonSchema(desc, nameDesc string) providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: desc,
		Attributes: map[string]*configschema.Attribute{
			"id":      {Type: cty.String, Computed: true},
			"name":    {Type: cty.String, Required: true, Description: nameDesc},
			"in_sync": {Type: cty.Bool, Computed: true, Description: "Whether the host has this setting."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateName(cfg cty.Value, check func(string) error) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	if err := check(cfg.GetAttr("name").AsString()); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

// applySingleton sets the value; removing the resource leaves the host as it is.
func applySingleton(ctx context.Context, req providers.ApplyResourceChangeRequest, set func(context.Context, *hostConn, string) error) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := set(ctx, h, planned.GetAttr("name").AsString()); err != nil {
				return cty.NilVal, err
			}
			return withSync(planned, true), nil
		}, nil)
}

func hostnameSchema() providers.Schema {
	return singletonSchema("The host's name, set now and across reboots. On cloud images, cloud-init may reset it at boot unless preserve_hostname is true.",
		"Hostname, such as web1 or web1.example.com.")
}

func validateHostname(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, system.ValidateHostname)
}

func planHostname(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "hostname", true, []string{"name"})
}

func readHostname(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		static, live, err := system.ReadHostname(ctx, h)
		if err != nil {
			return cty.NilVal, err
		}
		name := prior.GetAttr("name").AsString()
		return withSync(prior, static == name && live == name), nil
	})
}

func applyHostname(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applySingleton(ctx, req, func(ctx context.Context, h *hostConn, name string) error {
		if err := system.ApplyHostname(ctx, h, name); err != nil {
			return fmt.Errorf("hostname %s: %w", name, err)
		}
		return nil
	})
}

func timezoneSchema() providers.Schema {
	return singletonSchema("The host's time zone.", "IANA time zone, such as Europe/Dublin or UTC.")
}

func validateTimezone(cfg cty.Value) tfdiags.Diagnostics {
	return validateName(cfg, system.ValidateTimezone)
}

func planTimezone(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "timezone", true, []string{"name"})
}

func readTimezone(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		zone, err := system.ReadTimezone(ctx, h)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, zone == prior.GetAttr("name").AsString()), nil
	})
}

func applyTimezone(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applySingleton(ctx, req, func(ctx context.Context, h *hostConn, zone string) error {
		if err := system.ApplyTimezone(ctx, h, zone); err != nil {
			return fmt.Errorf("timezone %s: %w", zone, err)
		}
		return nil
	})
}
