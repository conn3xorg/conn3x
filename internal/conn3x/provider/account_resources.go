// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"math/big"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/account"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// Attributes the configuration may leave unset; the host's values are then
// recorded and left alone.
var userObserved = []string{"uid", "group", "groups", "home", "shell"}

func userSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "A local user account.",
			Attributes: map[string]*configschema.Attribute{
				"id":        {Type: cty.String, Computed: true},
				"revision":  revisionAttr(),
				"name":      {Type: cty.String, Required: true, Description: "Login name."},
				"uid":       {Type: cty.Number, Optional: true, Computed: true, Description: "User ID."},
				"group":     {Type: cty.String, Optional: true, Computed: true, Description: "Primary group."},
				"groups":    {Type: cty.Set(cty.String), Optional: true, Computed: true, Description: "Supplementary groups: the complete list."},
				"home":      {Type: cty.String, Optional: true, Computed: true, Description: "Home directory. Created with the user."},
				"shell":     {Type: cty.String, Optional: true, Computed: true, Description: "Login shell."},
				"system":    {Type: cty.Bool, Optional: true, Description: "Create as a system account."},
				"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the account, \"delete\" removes it and keeps its home directory."},
			},
			BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
		},
	}
}

// userSpec builds a spec from configuration: only what is set is managed.
func userSpec(cfg cty.Value) account.UserSpec {
	s := account.UserSpec{Name: cfg.GetAttr("name").AsString()}
	if v := cfg.GetAttr("uid"); known(v) {
		n, _ := v.AsBigFloat().Int64()
		i := int(n)
		s.UID = &i
	}
	for attr, dst := range map[string]**string{"group": &s.Group, "home": &s.Home, "shell": &s.Shell} {
		if v := cfg.GetAttr(attr); known(v) {
			str := v.AsString()
			*dst = &str
		}
	}
	if v := cfg.GetAttr("groups"); known(v) {
		groups := []string{}
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			groups = append(groups, e.AsString())
		}
		s.Groups = &groups
	}
	if v := cfg.GetAttr("system"); known(v) {
		s.System = v.True()
	}
	return s
}

// observedUser rebuilds what the host had from state.
func observedUser(state cty.Value) account.User {
	if !known(state.GetAttr("uid")) {
		return account.User{}
	}
	u := account.User{Exists: true}
	n, _ := state.GetAttr("uid").AsBigFloat().Int64()
	u.UID = int(n)
	u.Group = stringOr(state.GetAttr("group"), "")
	u.Home = stringOr(state.GetAttr("home"), "")
	u.Shell = stringOr(state.GetAttr("shell"), "")
	if v := state.GetAttr("groups"); known(v) {
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			u.Groups = append(u.Groups, e.AsString())
		}
	}
	return u
}

func known(v cty.Value) bool { return !v.IsNull() && v.IsWhollyKnown() }

func validateUser(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := userSpec(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planUser(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planAccount(req, "user", userObserved, func() bool {
		return account.UserNeedsChange(userSpec(req.Config), observedUser(req.PriorState))
	})
}

func readUser(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readAccount(ctx, req, func(ctx context.Context, host *hostConn, name string) (cty.Value, error) {
		u, err := account.ReadUser(ctx, host, name)
		if err != nil {
			return cty.NilVal, err
		}
		return userState(req.PriorState, u), nil
	})
}

func applyUser(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyAccount(ctx, req,
		func(ctx context.Context, host *hostConn) (cty.Value, error) {
			spec := userSpec(req.Config)
			if err := account.ApplyUser(ctx, host, spec); err != nil {
				return cty.NilVal, fmt.Errorf("user %s: %w", spec.Name, err)
			}
			u, err := account.ReadUser(ctx, host, spec.Name)
			if err != nil {
				return cty.NilVal, err
			}
			if account.UserNeedsChange(spec, u) {
				return cty.NilVal, fmt.Errorf("user %s does not match the configuration after applying", spec.Name)
			}
			return userState(req.PlannedState, u), nil
		},
		func(ctx context.Context, host *hostConn, name string) error {
			return account.DeleteUser(ctx, host, name)
		})
}

func userState(base cty.Value, u account.User) cty.Value {
	vals := base.AsValueMap()
	if !u.Exists {
		for _, a := range userObserved {
			vals[a] = cty.NullVal(vals[a].Type())
		}
		return cty.ObjectVal(vals)
	}
	vals["uid"] = cty.NumberIntVal(int64(u.UID))
	vals["group"] = cty.StringVal(u.Group)
	vals["home"] = cty.StringVal(u.Home)
	vals["shell"] = cty.StringVal(u.Shell)
	if len(u.Groups) == 0 {
		vals["groups"] = cty.SetValEmpty(cty.String)
	} else {
		var gs []cty.Value
		for _, g := range u.Groups {
			gs = append(gs, cty.StringVal(g))
		}
		vals["groups"] = cty.SetVal(gs)
	}
	return cty.ObjectVal(vals)
}

func groupSchema() providers.Schema {
	return providers.Schema{
		Block: &configschema.Block{
			Description: "A local group.",
			Attributes: map[string]*configschema.Attribute{
				"id":        {Type: cty.String, Computed: true},
				"revision":  revisionAttr(),
				"name":      {Type: cty.String, Required: true, Description: "Group name."},
				"gid":       {Type: cty.Number, Optional: true, Computed: true, Description: "Group ID."},
				"system":    {Type: cty.Bool, Optional: true, Description: "Create as a system group."},
				"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the group, \"delete\" removes it."},
			},
			BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
		},
	}
}

func groupSpec(cfg cty.Value) account.GroupSpec {
	s := account.GroupSpec{Name: cfg.GetAttr("name").AsString()}
	if v := cfg.GetAttr("gid"); known(v) {
		n, acc := v.AsBigFloat().Int64()
		if acc == big.Exact {
			i := int(n)
			s.GID = &i
		}
	}
	if v := cfg.GetAttr("system"); known(v) {
		s.System = v.True()
	}
	return s
}

func validateGroup(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := groupSpec(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planGroup(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planAccount(req, "group", []string{"gid"}, func() bool {
		g := account.Group{}
		if v := req.PriorState.GetAttr("gid"); known(v) {
			n, _ := v.AsBigFloat().Int64()
			g = account.Group{Exists: true, GID: int(n)}
		}
		return account.GroupNeedsChange(groupSpec(req.Config), g)
	})
}

func readGroup(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readAccount(ctx, req, func(ctx context.Context, host *hostConn, name string) (cty.Value, error) {
		g, err := account.ReadGroup(ctx, host, name)
		if err != nil {
			return cty.NilVal, err
		}
		return groupState(req.PriorState, g), nil
	})
}

func applyGroup(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyAccount(ctx, req,
		func(ctx context.Context, host *hostConn) (cty.Value, error) {
			spec := groupSpec(req.Config)
			if err := account.ApplyGroup(ctx, host, spec); err != nil {
				return cty.NilVal, fmt.Errorf("group %s: %w", spec.Name, err)
			}
			g, err := account.ReadGroup(ctx, host, spec.Name)
			if err != nil {
				return cty.NilVal, err
			}
			if account.GroupNeedsChange(spec, g) {
				return cty.NilVal, fmt.Errorf("group %s does not match the configuration after applying", spec.Name)
			}
			return groupState(req.PlannedState, g), nil
		},
		func(ctx context.Context, host *hostConn, name string) error {
			return account.DeleteGroup(ctx, host, name)
		})
}

func groupState(base cty.Value, g account.Group) cty.Value {
	vals := base.AsValueMap()
	vals["gid"] = cty.NullVal(cty.Number)
	if g.Exists {
		vals["gid"] = cty.NumberIntVal(int64(g.GID))
	}
	return cty.ObjectVal(vals)
}

// planAccount is the plan logic users and groups share. observed lists the
// attributes recorded from the host; they become unknown when a change is
// planned, except where the configuration sets them.
func planAccount(req providers.PlanResourceChangeRequest, kind string, observed []string, needsChange func() bool) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	host := req.ProposedNewState.GetAttr("ssh").GetAttr("host")
	if name := vals["name"]; name.IsKnown() {
		vals["id"] = planID(req, kind, name.AsString())
	} else {
		vals["id"] = cty.UnknownVal(cty.String)
	}
	if req.PriorState.IsNull() || !req.Config.IsWhollyKnown() || needsChange() {
		for _, a := range observed {
			if req.Config.GetAttr(a).IsNull() {
				vals[a] = cty.UnknownVal(vals[a].Type())
			}
		}
	}
	resp.PlannedState = cty.ObjectVal(vals)
	if !req.PriorState.IsNull() {
		if !req.PriorState.GetAttr("name").RawEquals(vals["name"]) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("name"))
		}
		if !req.PriorState.GetAttr("ssh").GetAttr("host").RawEquals(host) {
			resp.RequiresReplace = append(resp.RequiresReplace, cty.GetAttrPath("ssh").GetAttr("host"))
		}
	}
	return resp
}

func readAccount(ctx context.Context, req providers.ReadResourceRequest, read func(context.Context, *hostConn, string) (cty.Value, error)) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	host, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	state, err := read(ctx, host, req.PriorState.GetAttr("name").AsString())
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = state
	return resp
}

func applyAccount(ctx context.Context, req providers.ApplyResourceChangeRequest,
	apply func(context.Context, *hostConn) (cty.Value, error),
	remove func(context.Context, *hostConn, string) error) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	target := req.PlannedState
	if target.IsNull() {
		resp.NewState = target
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	host, err := dialForApply(ctx, target.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	if req.PlannedState.IsNull() {
		if err := remove(ctx, host, target.GetAttr("name").AsString()); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
		}
		return resp
	}
	state, err := apply(ctx, host)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = state
	return resp
}

func upgradeWith(schema func() providers.Schema) func(providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse {
	return func(req providers.UpgradeResourceStateRequest) providers.UpgradeResourceStateResponse {
		var resp providers.UpgradeResourceStateResponse
		val, err := ctyjson.Unmarshal(req.RawStateJSON, schema().Block.ImpliedType())
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
			return resp
		}
		resp.UpgradedState = val
		return resp
	}
}
