// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/lifecycle"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// conn3x_uri makes one HTTP call from the host when it's created, and again
// when its arguments or triggers change, as service_action restarts a unit.
// There's nothing on the host for a refresh to read.

// uriReplacing are the arguments whose change makes the call again.
var uriReplacing = []string{"url", "method", "headers", "body", "status_codes", "skip_tls_verify", "triggers"}

func uriSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Makes one HTTP call from the host when the step is first applied, and again whenever its arguments or triggers change, such as registering the host with a load balancer after a deploy. A refresh doesn't call it.",
		Attributes: map[string]*configschema.Attribute{
			"id":              {Type: cty.String, Computed: true},
			"url":             {Type: cty.String, Required: true, Description: "An http:// or https:// URL. The request is the host's: it goes through the SSH connection and leaves from the host, so 127.0.0.1 is the host, and it needs no curl there."},
			"method":          {Type: cty.String, Optional: true, Description: "GET (default), POST, PUT, PATCH, DELETE or HEAD."},
			"headers":         {Type: cty.Map(cty.String), Optional: true, Description: "Request headers, such as { \"Content-Type\" = \"application/json\" }."},
			"headers_wo":      {Type: cty.Map(cty.String), Optional: true, WriteOnly: true, Sensitive: true, Description: "Headers kept out of plan and state, such as an Authorization header. A change to them doesn't call again on its own: put a version of the secret in triggers for that."},
			"body":            {Type: cty.String, Optional: true, Description: "The request body, such as jsonencode({ host = \"web1\" })."},
			"body_wo":         {Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true, Description: "The body, kept out of plan and state. Set this or body."},
			"status_codes":    {Type: cty.List(cty.Number), Optional: true, Description: "The answers that count as success. Defaults to [200]. Redirects are followed first."},
			"skip_tls_verify": {Type: cty.Bool, Optional: true, Description: "true accepts any certificate for an https:// url."},
			"triggers":        {Type: cty.DynamicPseudoType, Optional: true, Description: "Any value; the call is made again whenever it changes."},
			"status":          {Type: cty.Number, Computed: true, Description: "The status the call got."},
			"response":        {Type: cty.String, Computed: true, Sensitive: true, Description: "The first MiB of the answer's body. Marked sensitive, since an API's answer often holds a token."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func uriFrom(v cty.Value) lifecycle.Request {
	r := lifecycle.Request{
		URLCheck: lifecycle.URLCheck{URL: stringOr(v.GetAttr("url"), ""), SkipTLSVerify: boolOr(v.GetAttr("skip_tls_verify"))},
		Method:   strings.ToUpper(stringOr(v.GetAttr("method"), "GET")),
		Body:     stringOr(v.GetAttr("body"), stringOr(v.GetAttr("body_wo"), "")),
		Headers:  map[string]string{},
	}
	for _, name := range []string{"headers", "headers_wo"} {
		if h := v.GetAttr(name); known(h) {
			for k, e := range h.AsValueMap() {
				r.Headers[k] = stringOr(e, "")
			}
		}
	}
	if codes := v.GetAttr("status_codes"); known(codes) {
		for _, c := range codes.AsValueSlice() {
			n, _ := c.AsBigFloat().Int64()
			r.StatusCodes = append(r.StatusCodes, int(n))
		}
	}
	return r
}

func validateURI(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	if m := cfg.GetAttr("method"); known(m) {
		switch strings.ToUpper(m.AsString()) {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD":
		default:
			diags = diags.Append(attrError("method", fmt.Sprintf("method %q must be GET, POST, PUT, PATCH, DELETE or HEAD", m.AsString())))
		}
	}
	if !cfg.GetAttr("body").IsNull() && !cfg.GetAttr("body_wo").IsNull() {
		diags = diags.Append(attrError("body_wo", "set body or body_wo, not both"))
	}
	if u := cfg.GetAttr("url"); known(u) {
		if err := uriFrom(cfg).URLCheck.Validate(); err != nil {
			diags = diags.Append(attrError("url", err.Error()))
		}
	}
	return diags
}

func planURI(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	// Write-only values never reach plan or state; apply reads them from
	// the configuration.
	vals["headers_wo"], vals["body_wo"] = cty.NullVal(cty.Map(cty.String)), cty.NullVal(cty.String)
	if u := vals["url"]; u.IsKnown() {
		vals["id"] = planID(req, "uri", u.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	if req.PriorState.IsNull() {
		vals["status"], vals["response"] = cty.UnknownVal(cty.Number), cty.UnknownVal(cty.String)
	} else {
		vals["status"], vals["response"] = req.PriorState.GetAttr("status"), req.PriorState.GetAttr("response")
		for _, name := range uriReplacing {
			if now := vals[name]; !now.IsWhollyKnown() || !req.PriorState.GetAttr(name).RawEquals(now) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(name))
			}
		}
		if len(resp.RequiresReplace) > 0 {
			vals["status"], vals["response"] = cty.UnknownVal(cty.Number), cty.UnknownVal(cty.String)
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// readURI keeps state as it is: a call leaves nothing on the host to read.
func readURI(_ context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return providers.ReadResourceResponse{NewState: req.PriorState}
}

func applyURI(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	resp.NewState = req.PlannedState
	// Only a create, which a change forces, makes the call. Removing the
	// step calls nothing.
	if req.PlannedState.IsNull() || !req.PriorState.IsNull() {
		return resp
	}
	h, err := dialForApply(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	got, err := lifecycle.Do(ctx, h, uriFrom(req.Config))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("uri: %w", err))
		return resp
	}
	vals := req.PlannedState.AsValueMap()
	vals["status"], vals["response"] = cty.NumberIntVal(int64(got.Status)), cty.StringVal(got.Body)
	vals["headers_wo"], vals["body_wo"] = cty.NullVal(cty.Map(cty.String)), cty.NullVal(cty.String)
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
