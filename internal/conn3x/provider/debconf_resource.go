// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/debconf"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func debconfSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A preset answer to a question a Debian or Ubuntu package asks when it installs, such as postfix's mailer type, so apt installs it without a prompt. Removing it leaves the answer as it is.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"name":     {Type: cty.String, Required: true, Description: "Package that owns the question, such as postfix."},
			"question": {Type: cty.String, Required: true, Description: "The question, such as postfix/main_mailer_type. debconf-show <package> on a host that has the package lists them with their answers."},
			"vtype":    {Type: cty.String, Required: true, Description: "The question's type, as the package's templates declare it: boolean, select, multiselect, string, password, text, note, title or error."},
			"value":    {Type: cty.String, Optional: true, Description: "The answer, as debconf-set-selections takes it: true or false for a boolean, the choices separated by \", \" for a multiselect. State keeps it, so put a password in value_wo. Set exactly one of value and value_wo."},
			"value_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Write-only: the answer, kept out of plan and state, for a password question. State records only value_hmac. debconf-show hides a password, so a refresh asks debconf itself for the answer the host has and compares its HMAC, which is how a password changed on the host shows as drift.",
			},
			"value_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of value_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null with value."},
			"in_sync":    {Type: cty.Bool, Computed: true, Description: "Whether debconf on the host has the answer."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func debconfFrom(v cty.Value, value string) debconf.Selection {
	return debconf.Selection{Package: v.GetAttr("name").AsString(), Question: v.GetAttr("question").AsString(),
		Type: v.GetAttr("vtype").AsString(), Value: value}
}

// debconfHMAC is what state records for value_wo.
func debconfHMAC(key []byte, v cty.Value, value string) string {
	return contentHMAC(key, "debconf:"+v.GetAttr("name").AsString()+":"+v.GetAttr("question").AsString(), value)
}

func validateDebconf(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !settled(cfg) {
		return diags
	}
	value, wo := cfg.GetAttr("value"), cfg.GetAttr("value_wo")
	if value.IsNull() == wo.IsNull() {
		return diags.Append(attrError("value", "set exactly one of value and value_wo"))
	}
	if value.IsNull() {
		value = wo
	}
	if err := debconfFrom(cfg, value.AsString()).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

// planDebconf keeps value_wo out of the plan and state, which record only
// value_hmac, so a new answer plans a change.
func planDebconf(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if req.ProposedNewState.IsNull() {
		return providers.PlanResourceChangeResponse{PlannedState: req.ProposedNewState}
	}
	vals := req.ProposedNewState.AsValueMap()
	vals["value_wo"] = cty.NullVal(cty.String)
	vals["value_hmac"] = cty.NullVal(cty.String)
	var warning error
	if wo := req.Config.GetAttr("value_wo"); !wo.IsNull() {
		vals["value_hmac"] = cty.UnknownVal(cty.String)
		key, err := hmacKey(true)
		if err == nil && !req.PriorState.IsNull() {
			if stored := req.PriorState.GetAttr("value_hmac"); known(stored) {
				err = checkHMACKey(stored.AsString(), key)
			}
		}
		if err != nil {
			var resp providers.PlanResourceChangeResponse
			resp.Diagnostics = resp.Diagnostics.Append(attrError("value_wo", err.Error()))
			return resp
		}
		warning = hmacKeyPermissionWarning()
		if wo.IsKnown() && known(vals["name"]) && known(vals["question"]) {
			vals["value_hmac"] = cty.StringVal(debconfHMAC(key, req.ProposedNewState, wo.AsString()))
		}
	}
	req.ProposedNewState = cty.ObjectVal(vals)
	resp := planSynced(req, "debconf", []string{"name", "question"}, []string{"vtype", "value", "value_hmac"})
	if warning != nil {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(warning.Error()))
	}
	return resp
}

func readDebconf(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		live, exists, err := debconf.Read(ctx, h, debconfFrom(prior, ""))
		if err != nil {
			return cty.NilVal, fmt.Errorf("debconf: %w", err)
		}
		if value := prior.GetAttr("value"); !value.IsNull() {
			return withSync(prior, exists && live == value.AsString()), nil
		}
		// Reading never creates a key: a new one here would only mismatch.
		key, err := hmacKey(false)
		if err == nil {
			err = checkHMACKey(prior.GetAttr("value_hmac").AsString(), key)
		}
		if err != nil {
			return cty.NilVal, fmt.Errorf("debconf value_wo: %w", err)
		}
		return withSync(prior, exists && debconfHMAC(key, prior, live) == prior.GetAttr("value_hmac").AsString()), nil
	})
}

func applyDebconf(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			vals := planned.AsValueMap()
			vals["value_wo"] = cty.NullVal(cty.String)
			value := planned.GetAttr("value")
			if wo := req.Config.GetAttr("value_wo"); !wo.IsNull() {
				value = wo
				// A saved plan applied elsewhere must use the key it was made with.
				key, err := hmacKey(true)
				if err == nil && known(planned.GetAttr("value_hmac")) {
					err = checkHMACKey(planned.GetAttr("value_hmac").AsString(), key)
				}
				if err != nil {
					return cty.NilVal, fmt.Errorf("debconf value_wo: %w", err)
				}
				vals["value_hmac"] = cty.StringVal(debconfHMAC(key, planned, wo.AsString()))
			}
			if value.IsNull() {
				return cty.NilVal, errors.New("debconf: value_wo didn't reach the apply; it's write-only, so set it in the step's config")
			}
			// apt and dpkg hold debconf's database while they configure a
			// package, so never overlap a package step on this host.
			unlock := lockHost(h, "packages")
			err := debconf.Apply(ctx, h, debconfFrom(planned, value.AsString()))
			unlock()
			if err != nil {
				return cty.NilVal, fmt.Errorf("debconf: %w", err)
			}
			return withSync(cty.ObjectVal(vals), true), nil
		}, nil)
}
