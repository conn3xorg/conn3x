// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/dircopy"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func dircopySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A directory copied from the machine Conn3x runs on to the host, file by file. Only files whose content, mode or owner differ are written, and the plan names them.",
		Attributes: map[string]*configschema.Attribute{
			"id":          {Type: cty.String, Computed: true},
			"revision":    revisionAttr(),
			"source":      {Type: cty.String, Required: true, Description: "The directory to copy, on the machine Conn3x runs on, such as \"${path.module}/site\". Regular files only: a link or a special file in it is an error."},
			"destination": {Type: cty.String, Required: true, Description: "The directory on the host, absolute, such as /var/www/site. Missing directories are made."},
			"mode":        {Type: cty.String, Optional: true, Computed: true, Description: "Every file's mode, such as \"0644\" (the default)."},
			"owner":       {Type: cty.String, Optional: true, Description: "Every file's owner. Unset leaves each file's owner as it is, or root's for a new one."},
			"group":       {Type: cty.String, Optional: true, Description: "Every file's group. Unset leaves it as it is."},
			"delete":      {Type: cty.Bool, Optional: true, Description: "true removes files under destination that the source doesn't have, as rsync --delete does. Off by default, so files put there by something else stay."},
			"files":       {Type: cty.Map(cty.String), Computed: true, Description: "Each file's path under destination and the SHA-256 of its content: what the source has in a plan, and what the host had at the last refresh, so the plan's diff names every file that will change."},
			"on_remove":   {Type: cty.String, Optional: true, Computed: true, Description: "What happens when this resource is removed: \"forget\" (default) leaves the files, \"delete\" removes the ones the source has."},
			"in_sync":     {Type: cty.Bool, Computed: true, Description: "Whether the host had every file, with its mode and owner, at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func dircopyFrom(v cty.Value) dircopy.Copy {
	c := dircopy.Copy{
		Source: stringOr(v.GetAttr("source"), ""),
		Dest:   stringOr(v.GetAttr("destination"), ""),
		Mode:   stringOr(v.GetAttr("mode"), defaultMode),
		Owner:  stringOr(v.GetAttr("owner"), ""),
		Group:  stringOr(v.GetAttr("group"), ""),
	}
	if d := v.GetAttr("delete"); known(d) {
		c.Delete = d.True()
	}
	return c
}

func validateDircopy(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := dircopyFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("destination", err.Error()))
	}
	return diags
}

func sumsValue(sums map[string]string) cty.Value {
	if len(sums) == 0 {
		return cty.MapValEmpty(cty.String)
	}
	m := map[string]cty.Value{}
	for k, v := range sums {
		m[k] = cty.StringVal(v)
	}
	return cty.MapVal(m)
}

// planDircopy reads the source here, at plan, so the planned files are
// what the source has: against the host's, from the last refresh, the diff
// is the list of files that will change.
func planDircopy(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if req.ProposedNewState.IsNull() || !req.ProposedNewState.IsWhollyKnown() {
		return planSynced(req, "directory_copy", []string{"destination"}, []string{"source", "mode", "owner", "group", "delete"})
	}
	c := dircopyFrom(req.ProposedNewState)
	files, err := c.Local()
	if err != nil {
		var resp providers.PlanResourceChangeResponse
		resp.Diagnostics = resp.Diagnostics.Append(attrError("source", err.Error()))
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	vals["mode"] = cty.StringVal(c.Mode)
	vals["files"] = sumsValue(dircopy.Sums(files))
	req.ProposedNewState = cty.ObjectVal(vals)
	return planSynced(req, "directory_copy", []string{"destination"}, []string{"source", "mode", "owner", "group", "delete", "files"})
}

// readDircopy records what the host has: the files the source has, and with
// delete the ones it doesn't, each with its sum. A file whose mode or owner
// is wrong is recorded with that, so it differs from the source's too.
func readDircopy(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	c := dircopyFrom(req.PriorState)
	client, err := dialConnection(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	have, err := dircopy.Read(ctx, client, c.Dest)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	want := map[string]string{}
	if f := req.PriorState.GetAttr("files"); known(f) {
		for k, v := range f.AsValueMap() {
			want[k] = v.AsString()
		}
	}
	recorded := map[string]string{}
	for rel, h := range have {
		if _, ours := want[rel]; !ours && !c.Delete {
			continue // not this step's file
		}
		sum := h.Sum
		// A file of the step's with the wrong mode or owner says so; a stray
		// one is only up for removal.
		if _, ours := want[rel]; ours && len(c.Diff(map[string]string{rel: h.Sum}, map[string]dircopy.Remote{rel: h}).Write) > 0 {
			sum += fmt.Sprintf(" (mode %s, owner %s:%s)", h.Mode, h.Owner, h.Group)
		}
		recorded[rel] = sum
	}
	vals := req.PriorState.AsValueMap()
	vals["files"] = sumsValue(recorded)
	vals["in_sync"] = cty.BoolVal(c.Diff(want, have).Empty())
	resp.NewState = cty.ObjectVal(vals)
	return resp
}

func applyDircopy(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	target := req.PlannedState
	removing := target.IsNull()
	if removing {
		resp.NewState = target
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		target = req.PriorState
	}
	c := dircopyFrom(target)
	if err := c.Validate(); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("destination", err.Error()))
		return resp
	}
	client, err := dialForApply(ctx, target.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	have, err := dircopy.Read(ctx, client, c.Dest)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	if removing {
		// Only the files the step copied: its last state's list.
		var plan dircopy.Plan
		for rel := range target.GetAttr("files").AsValueMap() {
			if _, ok := have[rel]; ok {
				plan.Remove = append(plan.Remove, rel)
			}
		}
		if err := c.Apply(ctx, client, nil, plan); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
		}
		return resp
	}
	files, err := c.Local()
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("source", err.Error()))
		return resp
	}
	sums := dircopy.Sums(files)
	if planned := target.GetAttr("files"); known(planned) && !sumsValue(sums).RawEquals(planned) {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("source", fmt.Sprintf("the files in %s changed after the plan; plan again", c.Source)))
		return resp
	}
	plan := c.Diff(sums, have)
	if len(plan.Write)+len(plan.Remove) > 0 {
		log.Printf("[INFO] conn3x: directory_copy to %s: writing %s; removing %s", c.Dest, list(plan.Write), list(plan.Remove))
	}
	if err := c.Apply(ctx, client, files, plan); err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	resp.NewState = withSync(target, true)
	return resp
}

func list(s []string) string {
	if len(s) == 0 {
		return "nothing"
	}
	return strings.Join(s, ", ")
}
