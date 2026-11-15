// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winDNSRecordSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: winExperimental + "One name's DNS records of one type, in a zone on a Windows DNS server such as a domain controller, owned as a set.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"zone":      {Type: cty.String, Required: true, Description: "The zone, such as corp.example.com. It must be on the server the step runs on."},
			"name":      {Type: cty.String, Required: true, Description: "The name in the zone, such as www, or @ for the zone itself."},
			"type":      {Type: cty.String, Required: true, Description: "\"A\", \"AAAA\", \"CNAME\", \"PTR\" or \"TXT\"."},
			"values":    {Type: cty.List(cty.String), Required: true, Description: "Every value the name has of this type: addresses for A and AAAA, so several make round robin, one host name for a CNAME, host names for PTR, text for TXT. Values not listed are removed."},
			"ttl":       {Type: cty.Number, Optional: true, Description: "Time to live, in seconds. Defaults to 3600."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the server when this resource is removed: \"forget\" (default) leaves the records, \"delete\" removes them."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the name had exactly these values, at this TTL, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func winDNSRecordFrom(v cty.Value) windows.DNSRecord {
	d := windows.DNSRecord{Zone: stringOr(v.GetAttr("zone"), ""), Name: stringOr(v.GetAttr("name"), ""), Type: stringOr(v.GetAttr("type"), ""), TTL: intOr(v.GetAttr("ttl"), 0)}
	if l := v.GetAttr("values"); known(l) {
		d.Values = stringList(l)
	}
	return d
}

func validateWinDNSRecord(cfg cty.Value) tfdiags.Diagnostics {
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return nil
	}
	diags := validateOnRemove(cfg)
	if err := winDNSRecordFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("values", err.Error()))
	}
	return diags
}

func planWinDNSRecord(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSyncedFold(req, "windows_dns_record", []string{"zone", "name", "type"}, []string{"values", "ttl"})
}

func readWinDNSRecord(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	d := winDNSRecordFrom(req.PriorState)
	a, err := windows.ReadDNSRecord(ctx, h.client, d)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(req.PriorState, d.Matches(a))
	return resp
}

func applyWinDNSRecord(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyWinStep(ctx, req, "windows_dns_record", func(ctx context.Context, h *hostConn, v cty.Value, remove bool) error {
		if remove {
			return windows.ApplyDNSRecordRemove(ctx, h.client, winDNSRecordFrom(v))
		}
		return windows.ApplyDNSRecord(ctx, h.client, winDNSRecordFrom(v))
	})
}
