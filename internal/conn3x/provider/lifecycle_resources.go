// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/lifecycle"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

const defaultRebootWait = 10 * time.Minute

// durationOr parses an optional duration attribute.
func durationOr(v cty.Value, fallback time.Duration) (time.Duration, error) {
	s := stringOr(v, "")
	if s == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("timeout %q must be a positive duration, such as \"90s\" or \"10m\"", s)
	}
	return d, nil
}

func waitForSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Waits until a path exists or a TCP port is listening on the host. Refresh checks again, so a later apply waits again if it stopped.",
		Attributes: map[string]*configschema.Attribute{
			"id":      {Type: cty.String, Computed: true},
			"path":    {Type: cty.String, Optional: true, Description: "Path to wait for. Set this or port."},
			"port":    {Type: cty.Number, Optional: true, Description: "TCP port to wait for a listener on. Set this or path."},
			"timeout": {Type: cty.String, Optional: true, Description: "How long to wait. Defaults to \"5m\"."},
			"in_sync": {Type: cty.Bool, Computed: true, Description: "Whether it was ready at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func waitForFrom(v cty.Value) (lifecycle.WaitFor, error) {
	w := lifecycle.WaitFor{Path: stringOr(v.GetAttr("path"), "")}
	if p := v.GetAttr("port"); !p.IsNull() {
		n, _ := p.AsBigFloat().Int64()
		w.Port = int(n)
	}
	var err error
	w.Timeout, err = durationOr(v.GetAttr("timeout"), lifecycle.DefaultWait)
	return w, err
}

func validateWaitFor(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	w, err := waitForFrom(cfg)
	if err == nil {
		err = w.Validate()
	}
	if err != nil {
		diags = diags.Append(attrError("path", err.Error()))
	}
	return diags
}

func planWaitFor(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "wait_for", []string{"path", "port"}, nil)
}

func readWaitFor(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		w, err := waitForFrom(prior)
		if err != nil {
			return cty.NilVal, err
		}
		ok, err := w.Ready(ctx, h)
		if err != nil {
			return cty.NilVal, err
		}
		return withSync(prior, ok), nil
	})
}

func applyWaitFor(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			w, err := waitForFrom(planned)
			if err == nil {
				err = w.Wait(ctx, h)
			}
			if err != nil {
				return cty.NilVal, fmt.Errorf("wait_for: %w", err)
			}
			return withSync(planned, true), nil
		}, nil)
}

func rebootSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Reboots the host when created and whenever triggers change, then waits for it to come back. Removing it does nothing.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"triggers": {Type: cty.Map(cty.String), Optional: true, Description: "Reboot again whenever any of these values change."},
			"timeout":  {Type: cty.String, Optional: true, Description: "How long to wait for the host to come back. Defaults to \"10m\"."},
			"boot_id":  {Type: cty.String, Computed: true, Description: "The host's boot ID after the reboot."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateReboot(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.GetAttr("timeout").IsKnown() {
		return diags
	}
	if _, err := durationOr(cfg.GetAttr("timeout"), defaultRebootWait); err != nil {
		diags = diags.Append(attrError("timeout", err.Error()))
	}
	return diags
}

func planReboot(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	vals["id"] = cty.UnknownVal(cty.String)
	if host := req.ProposedNewState.GetAttr("ssh").GetAttr("host"); host.IsKnown() {
		vals["id"] = cty.StringVal(host.AsString() + ":reboot")
	}
	switch {
	case req.PriorState.IsNull():
		vals["boot_id"] = cty.UnknownVal(cty.String)
	case !req.PriorState.GetAttr("triggers").RawEquals(vals["triggers"]):
		resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("triggers"))
		vals["boot_id"] = cty.UnknownVal(cty.String)
	case !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(req.ProposedNewState.GetAttr("ssh").GetAttr("host")):
		resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		vals["boot_id"] = cty.UnknownVal(cty.String)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readReboot(_ context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return providers.ReadResourceResponse{NewState: req.PriorState}
}

// applyReboot reboots and redials until the host reports a new boot ID.
func applyReboot(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	// A known boot_id means the plan did not ask for a reboot.
	if req.PlannedState.IsNull() || req.PlannedState.GetAttr("boot_id").IsKnown() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reboot: %w", err))
		return resp
	}
	wait, err := durationOr(req.PlannedState.GetAttr("timeout"), defaultRebootWait)
	if err != nil {
		return fail(err)
	}
	conn := req.PlannedState.GetAttr("ssh")
	h, err := dialConnection(ctx, conn)
	if err != nil {
		return fail(err)
	}
	before, err := lifecycle.BootID(ctx, h)
	if err != nil {
		return fail(err)
	}
	if err := lifecycle.ScheduleReboot(ctx, h); err != nil {
		return fail(err)
	}
	// Drop the pooled connection; the next dial makes a new one.
	_ = h.client.Close()

	deadline := time.Now().Add(wait)
	for {
		select {
		case <-ctx.Done():
			return fail(ctx.Err())
		case <-time.After(5 * time.Second):
		}
		if h, err := dialConnection(ctx, conn); err == nil {
			if now, err := lifecycle.BootID(ctx, h); err == nil && now != before {
				vals := req.PlannedState.AsValueMap()
				vals["boot_id"] = cty.StringVal(now)
				resp.NewState = cty.ObjectVal(vals)
				return resp
			}
		}
		if time.Now().After(deadline) {
			return fail(fmt.Errorf("the host did not come back within %s", wait))
		}
	}
}
