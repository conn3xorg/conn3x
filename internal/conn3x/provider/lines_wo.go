// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/setcfg"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// linesWO is lines_wo on a network config step: write-only lines that
// hold a secret. State keeps an HMAC of them, lines_hmac, and how each
// starts up to its secret, lines_wo_prefixes, which a refresh checks the
// device has.
type linesWO struct {
	kind string // the step, such as "eos_config"
	// block is the attribute naming what the lines are under, so the HMAC
	// is tied to it: parents on EOS, prefix on Junos and VyOS.
	block string
	start func(line string) (string, error) // the line up to its secret
	norm  func(line string) string          // nil sends lines as written
}

func (w linesWO) id(v cty.Value) string {
	b := v.GetAttr(w.block)
	key := ""
	if b.Type().IsListType() {
		key = strings.Join(stringList(b), "\n")
	} else {
		key = stringOr(b, "")
	}
	return passwordID(w.kind, stringOr(v.GetAttr("ssh").GetAttr("host"), ""), key)
}

func (w linesWO) lines(v cty.Value) []string {
	lines := stringList(v.GetAttr("lines_wo"))
	if w.norm != nil {
		for i, l := range lines {
			lines[i] = w.norm(l)
		}
	}
	return lines
}

func (w linesWO) starts(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i], _ = w.start(l) // validate refused lines without one
	}
	return out
}

// plan records lines_hmac and lines_wo_prefixes in place of the lines,
// then plans as the step otherwise would.
func (w linesWO) plan(req providers.PlanResourceChangeRequest, plan func(providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse) providers.PlanResourceChangeResponse {
	if req.ProposedNewState.IsNull() {
		return plan(req)
	}
	var resp providers.PlanResourceChangeResponse
	vals := req.ProposedNewState.AsValueMap()
	vals["lines_wo"] = cty.NullVal(cty.List(cty.String))
	vals["lines_hmac"], vals["lines_wo_prefixes"] = cty.NullVal(cty.String), cty.NullVal(cty.List(cty.String))
	var warn error
	if wo := req.Config.GetAttr("lines_wo"); !wo.IsNull() {
		vals["lines_hmac"], vals["lines_wo_prefixes"] = cty.UnknownVal(cty.String), cty.UnknownVal(cty.List(cty.String))
		key, err := hmacKey(true)
		if err == nil && !req.PriorState.IsNull() {
			if stored := req.PriorState.GetAttr("lines_hmac"); known(stored) {
				err = checkHMACKey(stored.AsString(), key)
			}
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("lines_wo", err.Error()))
			return resp
		}
		warn = hmacKeyPermissionWarning()
		next := cty.ObjectVal(vals)
		if wo.IsWhollyKnown() && known(next.GetAttr("ssh").GetAttr("host")) && next.GetAttr(w.block).IsWhollyKnown() {
			lines := w.lines(req.Config)
			vals["lines_hmac"] = cty.StringVal(passwordHMAC(key, w.id(next), strings.Join(lines, "\n")))
			vals["lines_wo_prefixes"] = stringListVal(w.starts(lines))
		}
	}
	req.ProposedNewState = cty.ObjectVal(vals)
	resp = plan(req)
	if warn != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(warn.Error()))
	}
	return resp
}

// woApply is what an apply with lines_wo sends: the lines, which only the
// config holds, how each starts, and whether to send them all again
// because lines_hmac changed, since the device can't show which secret it
// holds. lines is nil when the step has no lines_wo.
type woApply struct {
	lines, starts []string
	resend        bool
	mac           string
}

func (w linesWO) prepare(req providers.ApplyResourceChangeRequest) (woApply, error) {
	if req.PlannedState.IsNull() || req.PlannedState.GetAttr("lines_hmac").IsNull() {
		return woApply{}, nil
	}
	var lines []string
	if !req.Config.IsNull() {
		lines = w.lines(req.Config)
	}
	if len(lines) == 0 {
		return woApply{}, errors.New(w.kind + ": lines_wo didn't reach the apply; it's write-only, so set it in the step's config")
	}
	key, err := hmacKey(true)
	if err != nil {
		return woApply{}, err
	}
	mac := passwordHMAC(key, w.id(req.PlannedState), strings.Join(lines, "\n"))
	return woApply{
		lines:  lines,
		starts: w.starts(lines),
		resend: req.PriorState.IsNull() || stringOr(req.PriorState.GetAttr("lines_hmac"), "") != mac,
		mac:    mac,
	}, nil
}

// finish keeps the lines out of the new state and records what a plan
// that didn't know them left unknown.
func (a woApply) finish(resp providers.ApplyResourceChangeResponse) providers.ApplyResourceChangeResponse {
	if resp.NewState.IsNull() {
		return resp
	}
	vals := resp.NewState.AsValueMap()
	vals["lines_wo"] = cty.NullVal(cty.List(cty.String))
	if a.mac != "" {
		vals["lines_hmac"], vals["lines_wo_prefixes"] = cty.StringVal(a.mac), stringListVal(a.starts)
	}
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

// setLinesWO adds lines_wo to a Junos or VyOS config step's schema.
func setLinesWO(s providers.Schema, example string) providers.Schema {
	s.Block.Attributes["lines"].Description += " State keeps them, so put statements holding a secret in lines_wo."
	s.Block.Attributes["lines_wo"] = &configschema.Attribute{Type: cty.List(cty.String), Optional: true, Sensitive: true, WriteOnly: true,
		Description: "Write-only: set statements whose last word is a secret, such as " + example + ", never kept in state. The device shows most secrets hashed or encrypted, so each is matched by its path, the statement without that word: it's in sync when the path holds a value. A change to any of them sets them all again."}
	s.Block.Attributes["lines_hmac"] = &configschema.Attribute{Type: cty.String, Computed: true, Description: "An HMAC of lines_wo, keyed outside state, so a change plans an update."}
	s.Block.Attributes["lines_wo_prefixes"] = &configschema.Attribute{Type: cty.List(cty.String), Computed: true, Description: "Each lines_wo statement's path, without its secret. A refresh checks these hold a value, and a removal deletes them."}
	return s
}

// validateSetLinesWO checks lines_wo with the step's other lines, and
// warns about a secret in lines.
func validateSetLinesWO(cfg cty.Value, c setcfg.Config, norm func(string) string) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	for _, l := range stringList(cfg.GetAttr("lines_wo")) {
		if norm != nil {
			l = norm(l)
		}
		c.Secrets = append(c.Secrets, l)
	}
	if err := c.Validate(); err != nil {
		return diags.Append(attrError("lines", err.Error()))
	}
	if slices.ContainsFunc(c.Lines, setcfg.LooksSecret) {
		diags = diags.Append(tfdiags.AttributeValue(tfdiags.Warning, "A line in lines holds a secret",
			"A statement in lines ends with a password, secret or key, and state keeps lines as written. Move it to lines_wo, which keeps only an HMAC.", cty.GetAttrPath("lines")))
	}
	return diags
}

// cliLinesWO are a Junos, VyOS or IOS config step's plan and apply with lines_wo.
func cliLinesWO(k cliKind, w linesWO, with func(v cty.Value, secrets, starts []string, resend bool) cliWant) (
	func(providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse,
	func(context.Context, providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse) {
	plan := func(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
		return w.plan(req, k.plan)
	}
	apply := func(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
		wo, err := w.prepare(req)
		if err != nil {
			var resp providers.ApplyResourceChangeResponse
			resp.Diagnostics = resp.Diagnostics.Append(attrError("lines_wo", err.Error()))
			return resp
		}
		kk := k
		if wo.lines != nil {
			kk.config = func(v cty.Value) cliWant { return with(v, wo.lines, wo.starts, wo.resend) }
		}
		return wo.finish(kk.apply(ctx, req))
	}
	return plan, apply
}
