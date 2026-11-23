// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func fetchSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Copies a file from the host to the machine running Conn3x, at apply, as Ansible's fetch does. State keeps only whether the copies match, never the content.",
		Attributes: map[string]*configschema.Attribute{
			"id":                {Type: cty.String, Computed: true},
			"revision":          revisionAttr(),
			"src":               {Type: cty.String, Required: true, Description: "The file on the host, absolute."},
			"dest":              {Type: cty.String, Required: true, Description: "Where the copy goes on the machine running Conn3x, relative to the directory Conn3x runs in. Give each host its own, such as \"certs/${each.key}.pem\"."},
			"fail_on_missing":   {Type: cty.Bool, Optional: true, Description: "Whether a missing src fails the apply. Defaults to true; with false, a missing src leaves dest as it is."},
			"on_remove":         {Type: cty.String, Optional: true, Computed: true, Description: "What happens when this resource is removed: \"forget\" (default) leaves the copy, \"delete\" deletes dest. The host's file is never touched."},
			"in_sync":           {Type: cty.Bool, Computed: true, Description: "Whether dest held what src did at the last refresh."},
			"earlier_revisions": {Type: cty.DynamicPseudoType, Optional: true, Description: "Set by the circuit, so leave it unset: the revisions of the steps before this one. A plan that changes any of them reads src again at apply time, so a file an earlier step writes comes back in the same apply."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func validateFetch(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if src := cfg.GetAttr("src"); src.IsKnown() && !src.IsNull() && !strings.HasPrefix(src.AsString(), "/") {
		diags = diags.Append(attrError("src", fmt.Sprintf("src must be an absolute path on the host, not %q", src.AsString())))
	}
	if dest := cfg.GetAttr("dest"); dest.IsKnown() && !dest.IsNull() {
		if d := dest.AsString(); d == "" || strings.HasSuffix(d, "/") {
			diags = diags.Append(attrError("dest", fmt.Sprintf("dest is the copy's file name, not a directory: %q", d)))
		}
	}
	return diags
}

// planFetch reads src again at apply when an earlier step is about to
// change, since it may write src after the refresh read it.
func planFetch(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planSynced(req, "fetch", []string{"dest"}, []string{"src", "fail_on_missing"})
	if req.PriorState.IsNull() || resp.PlannedState.IsNull() {
		return resp
	}
	earlier, was := resp.PlannedState.GetAttr("earlier_revisions"), req.PriorState.GetAttr("earlier_revisions")
	if !earlier.IsWhollyKnown() || !was.RawEquals(earlier) {
		vals := resp.PlannedState.AsValueMap()
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

// fetchSync reads src on the host and dest here, and says whether dest
// holds src. src is the content to write, or nil when there's nothing to.
func fetchSync(ctx context.Context, h *hostConn, v cty.Value) (src []byte, inSync bool, err error) {
	a, err := file.Read(ctx, h, stringOr(v.GetAttr("src"), ""))
	if err != nil {
		return nil, false, err
	}
	if !a.Exists {
		if f := v.GetAttr("fail_on_missing"); f.IsNull() || f.True() {
			return nil, false, fmt.Errorf("%s isn't on the host; set fail_on_missing = false if that's expected", stringOr(v.GetAttr("src"), ""))
		}
		return nil, true, nil
	}
	have, err := os.ReadFile(stringOr(v.GetAttr("dest"), ""))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	return []byte(a.Content), err == nil && string(have) == a.Content, nil
}

func readFetch(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		_, ok, err := fetchSync(ctx, h, prior)
		if err != nil {
			// A missing src fails the apply, not the refresh.
			return withSync(prior, false), nil
		}
		return withSync(prior, ok), nil
	})
}

func applyFetch(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			content, ok, err := fetchSync(ctx, h, planned)
			if err == nil && !ok && content != nil {
				err = writeFetched(stringOr(planned.GetAttr("dest"), ""), content)
			}
			if err != nil {
				return cty.NilVal, fmt.Errorf("fetch: %w", err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			err := os.Remove(stringOr(prior.GetAttr("dest"), ""))
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		})
}

// writeFetched writes content to dest through a file beside it, so a
// reader never sees half a copy, readable by its owner only, since what's
// fetched is often a key or a token.
func writeFetched(dest string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+filepath.Base(dest)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}
