// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/sshkey"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func knownHostsSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A remote host's SSH key in a known_hosts file, which should or should not be there. The rest of the file stays as it is.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"host":      {Type: cty.String, Required: true, Description: "The remote host: a lowercase name or address, or [host]:port for another port."},
			"key":       {Type: cty.String, Optional: true, Description: "The host's public key: the type, the key and an optional comment. Required unless state is \"absent\"."},
			"user":      {Type: cty.String, Optional: true, Description: "Whose ~/.ssh/known_hosts to change. Without it, the host's /etc/ssh/ssh_known_hosts, which every user trusts."},
			"state":     {Type: cty.String, Optional: true, Description: "\"present\" (default), or \"absent\", which removes all of this host's keys."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"delete\" (default) removes the key, so a retired key stops being trusted; \"forget\" leaves it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the file already matches."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateKnownHosts(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	state := stringOr(cfg.GetAttr("state"), "present")
	key := stringOr(cfg.GetAttr("key"), "")
	switch {
	case state != "present" && state != "absent":
		diags = diags.Append(attrError("state", fmt.Sprintf("state must be \"present\" or \"absent\", not %q", state)))
	case state == "present" && key == "":
		diags = diags.Append(attrError("key", "key is required unless state is \"absent\""))
	case state == "absent" && key != "":
		diags = diags.Append(attrError("key", "leave key out with state = \"absent\": it removes all of this host's keys"))
	}
	if user := stringOr(cfg.GetAttr("user"), ""); !cfg.GetAttr("user").IsNull() {
		if err := (account.UserSpec{Name: user}).Validate(); err != nil {
			diags = diags.Append(attrError("user", err.Error()))
		}
	}
	if err := sshkey.ValidateKnownHost(cfg.GetAttr("host").AsString(), key); err != nil {
		diags = diags.Append(attrError("host", err.Error()))
	}
	return diags
}

func planKnownHosts(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := deleteByDefault(req).ProposedNewState.AsValueMap()
	if h, u := vals["host"], vals["user"]; h.IsKnown() && u.IsKnown() {
		vals["id"] = planID(req, "known_hosts", stringOr(u, "system"), h.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	stale := req.PriorState.IsNull()
	if !stale {
		for _, a := range []string{"host", "key", "user"} {
			if !req.PriorState.GetAttr(a).RawEquals(vals[a]) {
				resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath(a))
				stale = true
			}
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(req.ProposedNewState.GetAttr("ssh").GetAttr("host")) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
		if s := req.PriorState.GetAttr("in_sync"); !known(s) || s.False() || !req.PriorState.GetAttr("state").RawEquals(vals["state"]) {
			stale = true
		}
	}
	vals["in_sync"] = cty.True
	if stale {
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
	}
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func readKnownHosts(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		vals := prior.AsValueMap()
		var content string
		if user := prior.GetAttr("user"); user.IsNull() {
			actual, err := file.Read(ctx, h, sshkey.SystemKnownHosts)
			if err != nil {
				return cty.NilVal, err
			}
			content = actual.Content
		} else {
			loc, err := sshkey.LocateKnownHosts(ctx, h, user.AsString())
			if err != nil {
				vals["in_sync"] = cty.False
				return cty.ObjectVal(vals), nil
			}
			if content, err = sshkey.Read(ctx, h, loc); err != nil {
				return cty.NilVal, err
			}
		}
		edited, err := sshkey.EditKnownHosts(content, prior.GetAttr("host").AsString(), stringOr(prior.GetAttr("key"), ""), keyPresent(prior))
		if err != nil {
			return cty.NilVal, err
		}
		vals["in_sync"] = cty.BoolVal(edited == content)
		return cty.ObjectVal(vals), nil
	})
}

// changeKnownHost edits the file a step names. Steps on one file take turns:
// a host often has several keys, and a for_each runs them together.
func changeKnownHost(ctx context.Context, h *hostConn, v cty.Value, present bool) error {
	host, key := v.GetAttr("host").AsString(), stringOr(v.GetAttr("key"), "")
	if user := v.GetAttr("user"); !user.IsNull() {
		defer lockHost(h, "known_hosts\x00"+user.AsString())()
		loc, err := sshkey.LocateKnownHosts(ctx, h, user.AsString())
		if err != nil {
			return err
		}
		return sshkey.ApplyKnownHost(ctx, h, loc, host, key, present)
	}
	if !present {
		// Nothing to remove from a missing file, and no reason to create it.
		if actual, err := file.Read(ctx, h, sshkey.SystemKnownHosts); err != nil {
			return err
		} else if !actual.Exists {
			return nil
		}
	}
	target, err := editTarget(ctx, h, sshkey.SystemKnownHosts)
	if err != nil {
		return err
	}
	return editFile(ctx, h, target, present, func(s string) (string, error) {
		return sshkey.EditKnownHosts(s, host, key, present)
	})
}

func applyKnownHosts(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			if err := changeKnownHost(ctx, h, planned, keyPresent(planned)); err != nil {
				return cty.NilVal, fmt.Errorf("known host %s: %w", planned.GetAttr("host").AsString(), err)
			}
			vals := planned.AsValueMap()
			vals["in_sync"] = cty.True
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			// A step that kept a host out has nothing to take back.
			if !keyPresent(prior) {
				return nil
			}
			return changeKnownHost(ctx, h, prior, false)
		})
}
