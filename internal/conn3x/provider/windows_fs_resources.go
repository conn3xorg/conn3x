// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/windows"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func winEntryBlock(desc string) *configschema.NestedBlock {
	return &configschema.NestedBlock{
		Nesting: configschema.NestingList,
		Block: configschema.Block{
			Description: desc,
			Attributes: map[string]*configschema.Attribute{
				"principal":   {Type: cty.String, Required: true, Description: "A user, group or SID, such as BUILTIN\\Users or S-1-5-32-545."},
				"rights":      {Type: cty.List(cty.String), Required: true, Description: "Any of FullControl, Modify, ReadAndExecute, Read, Write, Delete, ReadPermissions, ChangePermissions and TakeOwnership."},
				"type":        {Type: cty.String, Optional: true, Description: "\"allow\" (default) or \"deny\"."},
				"inheritance": {Type: cty.String, Optional: true, Description: "What below a folder also gets this rule: \"none\", \"object\", \"container\" or \"container,object\". Defaults to \"container,object\" on a folder and \"none\" on a file."},
			},
		},
	}
}

func winEntries(v cty.Value) []windows.Entry {
	if !known(v) {
		return nil
	}
	var out []windows.Entry
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		en := windows.Entry{
			Principal:   e.GetAttr("principal").AsString(),
			Type:        stringOr(e.GetAttr("type"), ""),
			Inheritance: stringOr(e.GetAttr("inheritance"), ""),
		}
		for r := e.GetAttr("rights").ElementIterator(); r.Next(); {
			_, s := r.Element()
			en.Rights = append(en.Rights, s.AsString())
		}
		out = append(out, en)
	}
	return out
}

func validateWinEntries(cfg cty.Value, block string) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if v := cfg.GetAttr(block); known(v) {
		if err := windows.ValidateEntries(winEntries(v)); err != nil {
			diags = diags.Append(attrError(block, err.Error()))
		}
	}
	return diags
}

func validateWinPathAttr(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if p := cfg.GetAttr("path"); known(p) {
		if _, err := windows.CleanLocalPath("path", p.AsString()); err != nil {
			diags = diags.Append(attrError("path", err.Error()))
		}
	}
	return diags
}

func winPath(v cty.Value) (string, error) {
	return windows.CleanLocalPath("path", v.GetAttr("path").AsString())
}

// winFileInSync reports whether a path's rules are the ones configured. A file
// or folder with no list of its own has nothing to compare.
func winFileInSync(s windows.PathState, entries []windows.Entry) (bool, error) {
	if len(entries) == 0 {
		return true, nil
	}
	return windows.Exact(s, entries)
}

func winFileSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A file on a Windows host, written byte for byte: no line ending conversion. It never writes through a link, and refuses a folder on the way that another account could change.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"path":     {Type: cty.String, Required: true, Description: "Full path on a local drive, such as C:\\app\\config.json. Its folder must already exist."},
			"content":  {Type: cty.String, Optional: true, Description: "Exact content, up to 2 MiB. Set this or content_wo, or source_path."},
			"content_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Exact content, kept out of state: state records only content_hmac. Use it for secrets. Unless acl is set, only SYSTEM and Administrators can read the file. Set this or content, or source_path.",
			},
			"source_path": {
				Type: cty.String, Optional: true,
				Description: "Full path of a file on the same host to copy to path, such as a sample config an installer leaves. Set this or content, or content_wo. Every plan hashes both files on the host, and neither file's content goes into the plan or state.",
			},
			"source_sha256": {Type: cty.String, Computed: true, Description: "With source_path, SHA-256 of the source file when it was last read, hex encoded. Null when it was missing, or without source_path."},
			"content_hmac":  {Type: cty.String, Computed: true, Description: "HMAC-SHA256 over the path and the SHA-256 of content_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null when content is used."},
			"sha256":        {Type: cty.String, Computed: true, Description: "SHA-256 of the file, hex encoded. Null with content_wo, and sensitive when content is."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the file, \"delete\" removes it."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the file's rules matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{
			"ssh": connectionBlock(),
			"acl": winEntryBlock("The file's whole list of access rules, in place before any content is written, and nothing inherited. Without it, a new file inherits from its folder, and a file already there keeps its rules. Include whoever Conn3x logs in as, or later reads will fail."),
		},
	}}
}

func validateWinFile(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	diags = diags.Append(validateWinPathAttr(cfg))
	diags = diags.Append(validateWinEntries(cfg, "acl"))
	content, wo, src := cfg.GetAttr("content"), cfg.GetAttr("content_wo"), cfg.GetAttr("source_path")
	set := 0
	for _, v := range []cty.Value{content, wo, src} {
		if !v.IsNull() {
			set++
		}
	}
	if set != 1 {
		diags = diags.Append(attrError("content", "set exactly one of content, content_wo and source_path"))
	}
	if known(src) {
		if _, err := windows.CleanLocalPath("source_path", src.AsString()); err != nil {
			diags = diags.Append(attrError("source_path", err.Error()))
		}
	}
	if known(content) && len(content.AsString()) > windows.MaxContent {
		diags = diags.Append(attrError("content", "content is larger than 2 MiB"))
	}
	if known(wo) && len(wo.AsString()) > windows.MaxContent {
		diags = diags.Append(attrError("content_wo", "content_wo is larger than 2 MiB"))
	}
	return diags
}

// winWoHMAC is what state records for write-only content. It's over the hash,
// so a read can compare it knowing only the hash on the host: the secret itself
// never comes back.
func winWoHMAC(key []byte, path, sha string) string {
	return contentHMAC(key, path, "sha256:"+sha)
}

func planWinFile(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	var resp providers.PlanResourceChangeResponse
	if req.ProposedNewState.IsNull() {
		resp.PlannedState = req.ProposedNewState
		return resp
	}
	vals := req.ProposedNewState.AsValueMap()
	if vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
	}
	stale := req.PriorState.IsNull()
	vals["source_sha256"] = cty.NullVal(cty.String)
	if src := vals["source_path"]; !src.IsNull() {
		vals["content_hmac"] = cty.NullVal(cty.String)
		vals["sha256"], vals["source_sha256"] = planCopy(req.PriorState, src)
	} else if wo := req.Config.GetAttr("content_wo"); !wo.IsNull() {
		vals["content"], vals["content_wo"], vals["sha256"] = cty.NullVal(cty.String), cty.NullVal(cty.String), cty.NullVal(cty.String)
		vals["content_hmac"] = cty.UnknownVal(cty.String)
		key, err := writeKey(req.PriorState)
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("content_wo", err.Error()))
			return resp
		}
		if err := hmacKeyPermissionWarning(); err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(err.Error()))
		}
		if path := vals["path"]; wo.IsKnown() && path.IsKnown() {
			vals["content_hmac"] = cty.StringVal(winWoHMAC(key, path.AsString(), digest(wo.AsString())))
		}
	} else {
		vals["content_hmac"] = cty.NullVal(cty.String)
		vals["sha256"] = cty.UnknownVal(cty.String)
		if c := vals["content"]; c.IsKnown() {
			vals["sha256"] = cty.StringVal(digest(c.AsString()))
		}
	}
	if !stale {
		s := req.PriorState.GetAttr("in_sync")
		stale = !known(s) || s.False() || !req.PriorState.GetAttr("acl").RawEquals(vals["acl"])
	}
	vals["in_sync"] = cty.True
	if stale {
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
	}
	resp = finishFilePlan(req, resp, vals)
	// A copy that applies for any reason, even only its rules, copies the
	// source again, which an earlier step in the same apply may have
	// changed: its hashes can't be promised.
	if !vals["source_path"].IsNull() && known(vals["sha256"]) && !resp.PlannedState.RawEquals(req.PriorState) {
		vals["sha256"], vals["source_sha256"] = cty.UnknownVal(cty.String), cty.UnknownVal(cty.String)
		resp.PlannedState = cty.ObjectVal(vals)
	}
	return resp
}

func readWinFile(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	path, err := winPath(req.PriorState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	entries := winFileEntries(req.PriorState, !req.PriorState.GetAttr("content_hmac").IsNull())
	s, err := windows.ReadPath(ctx, h.raw(), path, windows.Principals(entries, ""), true)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading %s: %w", path, err))
		return resp
	}
	if s.Kind == "missing" && s.LinkOnWay == "" {
		resp.NewState = cty.NullVal(req.PriorState.Type())
		return resp
	}
	key, err := woKey(req.PriorState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("content_wo", err.Error()))
		return resp
	}
	inSync := s.Kind == "file" && s.LinkOnWay == ""
	if inSync {
		if inSync, err = winFileInSync(s, entries); err != nil {
			// A principal that's gone from the host is drift; apply reports it.
			inSync = false
		}
	}
	resp.NewState = winFileState(req.PriorState, s.SHA256, key, inSync)
	if src := req.PriorState.GetAttr("source_path"); !src.IsNull() {
		sum, err := winSourceSum(ctx, h, src.AsString())
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(err)
			return resp
		}
		resp.NewState = withSourceSum(resp.NewState, sum)
	}
	return resp
}

// winSourceSum hashes a copy's source on the host: "" when it's missing.
// A folder or a link, there or on the way, is an error, as it is at path.
func winSourceSum(ctx context.Context, h *hostConn, src string) (string, error) {
	src, err := windows.CleanLocalPath("source_path", src)
	if err != nil {
		return "", err
	}
	s, err := windows.ReadPath(ctx, h.raw(), src, nil, true)
	switch {
	case err != nil:
		return "", fmt.Errorf("reading source_path %s: %w", src, err)
	case s.LinkOnWay != "":
		return "", fmt.Errorf("source_path %s has a link or junction on the way, at %s, which Conn3x won't follow. Use the real path", src, s.LinkOnWay)
	case s.Kind == "missing":
		return "", nil
	case s.Kind == "link":
		return "", fmt.Errorf("source_path %s is a link or junction, which Conn3x won't follow. Use the real path", src)
	case s.Kind != "file":
		return "", fmt.Errorf("source_path %s is a folder, not a file", src)
	}
	return s.SHA256, nil
}

// withSourceSum records a copy's source hash, null when it was missing.
func withSourceSum(state cty.Value, sum string) cty.Value {
	vals := state.AsValueMap()
	vals["source_sha256"] = cty.NullVal(cty.String)
	if sum != "" {
		vals["source_sha256"] = cty.StringVal(sum)
	}
	return cty.ObjectVal(vals)
}

// winFileEntries is the file's list of rules, or the default for a secret.
func winFileEntries(v cty.Value, secret bool) []windows.Entry {
	entries := winEntries(v.GetAttr("acl"))
	if len(entries) == 0 && secret {
		return windows.SecretEntries
	}
	return entries
}

func winFileState(base cty.Value, sha string, key []byte, inSync bool) cty.Value {
	vals := base.AsValueMap()
	vals["in_sync"] = cty.BoolVal(inSync)
	if key != nil {
		vals["content_hmac"] = cty.StringVal(winWoHMAC(key, vals["path"].AsString(), sha))
		return cty.ObjectVal(vals)
	}
	vals["sha256"] = cty.StringVal(sha)
	return cty.ObjectVal(vals)
}

func applyWinFile(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_file: %w", err))
		return resp
	}
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		if req.PriorState.IsNull() || req.PriorState.GetAttr("on_remove").AsString() != onRemoveDelete {
			return resp
		}
		h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
		if err != nil {
			return fail(err)
		}
		path, err := winPath(req.PriorState)
		if err != nil {
			return fail(err)
		}
		if err := windows.ApplyFileRemove(ctx, h.raw(), path); err != nil {
			return fail(err)
		}
		return resp
	}
	planned := req.PlannedState
	path, err := winPath(planned)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, planned.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	content, wo, src := "", req.Config.GetAttr("content_wo"), stringOr(planned.GetAttr("source_path"), "")
	var key []byte
	var secrets []string
	if src != "" {
		if src, err = windows.CleanLocalPath("source_path", src); err != nil {
			return fail(err)
		}
	} else if wo.IsNull() {
		content = planned.GetAttr("content").AsString()
	} else {
		content = wo.AsString()
		secrets = []string{content}
		if key, err = writeKey(req.PriorState); err == nil {
			// A saved plan applied elsewhere must use the key it was made with.
			err = checkHMACKey(planned.GetAttr("content_hmac").AsString(), key)
		}
		if err != nil {
			resp.Diagnostics = resp.Diagnostics.Append(attrError("content_wo", err.Error()))
			return resp
		}
	}
	entries := winFileEntries(planned, !wo.IsNull())
	want := digest(content)
	if src != "" {
		if want, err = winSourceSum(ctx, h, src); err != nil {
			return fail(err)
		}
		if want == "" {
			return fail(fmt.Errorf("source_path %s doesn't exist on the host; a step that creates it has to come first", src))
		}
	}
	before, err := windows.ReadPath(ctx, h.raw(), path, windows.Principals(entries, ""), true)
	if err != nil {
		return fail(errors.New(windows.Scrub(err.Error(), secrets)))
	}
	done := before.Kind == "file" && before.LinkOnWay == "" && before.SHA256 == want
	if done {
		if done, err = winFileInSync(before, entries); err != nil {
			return fail(err)
		}
	}
	if !done && src != "" {
		if err := windows.ApplyFileCopy(ctx, h.raw(), path, src, entries); err != nil {
			return fail(fmt.Errorf("copying %s to %s: %w", src, path, err))
		}
	} else if !done {
		if err := windows.ApplyFile(ctx, h.raw(), path, []byte(content), entries, secrets); err != nil {
			return fail(fmt.Errorf("writing %s: %w", path, err))
		}
	}
	after, err := windows.ReadPath(ctx, h.raw(), path, windows.Principals(entries, ""), true)
	if err != nil {
		return fail(fmt.Errorf("reading back %s: %w", path, err))
	}
	inSync, err := winFileInSync(after, entries)
	if err != nil {
		return fail(err)
	}
	if src != "" {
		// The source is hashed again: an earlier step in this apply, or
		// anything else, may have changed it since.
		if want, err = winSourceSum(ctx, h, src); err != nil {
			return fail(fmt.Errorf("reading back %s: %w", path, err))
		}
	}
	if after.Kind != "file" || after.SHA256 != want || !inSync {
		return fail(fmt.Errorf("%s does not match what was written; something else changed it", path))
	}
	resp.NewState = winFileState(planned, after.SHA256, key, true)
	if src != "" {
		resp.NewState = withSourceSum(resp.NewState, want)
	}
	return resp
}

func winDirectorySchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A folder on a Windows host, with any missing above it. Removing the step leaves the folder.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"path":     {Type: cty.String, Required: true, Description: "Full path on a local drive, such as C:\\app\\logs."},
			"in_sync":  {Type: cty.Bool, Computed: true, Description: "Whether the folder's rules matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{
			"ssh": connectionBlock(),
			"acl": winEntryBlock("The folder's whole list of access rules, in place from the moment it exists, and nothing inherited. Without it, a new folder inherits from the one above. Include whoever Conn3x logs in as."),
		},
	}}
}

func validateWinDirectory(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateWinPathAttr(cfg))
	return diags.Append(validateWinEntries(cfg, "acl"))
}

func planWinDirectory(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "windows_directory", []string{"path"}, []string{"acl"})
}

func readWinDirectory(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	path, err := winPath(req.PriorState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	entries := winEntries(req.PriorState.GetAttr("acl"))
	s, err := windows.ReadPath(ctx, h.raw(), path, windows.Principals(entries, ""), false)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading %s: %w", path, err))
		return resp
	}
	if s.Kind == "missing" && s.LinkOnWay == "" {
		resp.NewState = cty.NullVal(req.PriorState.Type())
		return resp
	}
	inSync := s.Kind == "directory" && s.LinkOnWay == ""
	if inSync {
		if inSync, err = winFileInSync(s, entries); err != nil {
			inSync = false
		}
	}
	resp.NewState = withSync(req.PriorState, inSync)
	return resp
}

func applyWinDirectory(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_directory: %w", err))
		return resp
	}
	path, err := winPath(req.PlannedState)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	entries := winEntries(req.PlannedState.GetAttr("acl"))
	if err := windows.ApplyDirectory(ctx, h.raw(), path, entries); err != nil {
		return fail(fmt.Errorf("making %s: %w", path, err))
	}
	s, err := windows.ReadPath(ctx, h.raw(), path, windows.Principals(entries, ""), false)
	if err != nil {
		return fail(err)
	}
	ok, err := winFileInSync(s, entries)
	if err != nil {
		return fail(err)
	}
	if s.Kind != "directory" || !ok {
		return fail(fmt.Errorf("%s does not match what was set; something else changed it", path))
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}

func winACLSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "Access rules on a file or folder that already exists on a Windows host. Rules are compared by SID, so names and case cause no difference. It won't follow a link. Removing the step leaves the rules as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":            {Type: cty.String, Computed: true},
			"revision":      revisionAttr(),
			"path":          {Type: cty.String, Required: true, Description: "Full path on a local drive."},
			"authoritative": {Type: cty.Bool, Optional: true, Description: "Remove any rule set directly on the path that isn't listed here. Defaults to false, which only adds. Rules it inherits stay; set inherit = false to drop those."},
			"inherit":       {Type: cty.Bool, Optional: true, Description: "Whether the path inherits rules from its folder. Left as it is when unset."},
			"owner":         {Type: cty.String, Optional: true, Description: "Owning user or group. Left as it is when unset."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the rules matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{
			"ssh":   connectionBlock(),
			"entry": winEntryBlock("One access rule."),
		},
	}}
}

func winACLFrom(v cty.Value) (windows.ACL, error) {
	path, err := winPath(v)
	if err != nil {
		return windows.ACL{}, err
	}
	a := windows.ACL{Path: path, Entries: winEntries(v.GetAttr("entry")), Owner: stringOr(v.GetAttr("owner"), "")}
	if au := v.GetAttr("authoritative"); known(au) {
		a.Authoritative = au.True()
	}
	if in := v.GetAttr("inherit"); known(in) {
		b := in.True()
		a.Inherit = &b
	}
	return a, nil
}

func validateWinACL(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateWinPathAttr(cfg))
	diags = diags.Append(validateWinEntries(cfg, "entry"))
	if v := cfg.GetAttr("owner"); known(v) {
		if err := windows.ValidateEntry(windows.Entry{Principal: v.AsString(), Rights: []string{"Read"}}); err != nil {
			diags = diags.Append(attrError("owner", err.Error()))
		}
	}
	e, in, o := cfg.GetAttr("entry"), cfg.GetAttr("inherit"), cfg.GetAttr("owner")
	if e.IsKnown() && in.IsKnown() && o.IsKnown() && (e.IsNull() || e.LengthInt() == 0) && in.IsNull() && o.IsNull() {
		diags = diags.Append(attrError("entry", "set at least one of entry, inherit and owner"))
	}
	return diags
}

func planWinACL(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "windows_acl", []string{"path"}, []string{"entry", "authoritative", "inherit", "owner"})
}

func winACLMatches(s windows.PathState, a windows.ACL) (bool, error) {
	return s.Matches(a.Entries, a.Authoritative, a.Inherit, a.Owner)
}

func readWinACL(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	resp := providers.ReadResourceResponse{NewState: req.PriorState}
	if req.PriorState.IsNull() {
		return resp
	}
	h, err := winHost(ctx, req.PriorState.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	a, err := winACLFrom(req.PriorState)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(err)
		return resp
	}
	s, err := windows.ReadPath(ctx, h.raw(), a.Path, windows.Principals(a.Entries, a.Owner), false)
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("reading %s: %w", a.Path, err))
		return resp
	}
	inSync := (s.Kind == "file" || s.Kind == "directory") && s.LinkOnWay == ""
	if inSync {
		if inSync, err = winACLMatches(s, a); err != nil {
			inSync = false
		}
	}
	resp.NewState = withSync(req.PriorState, inSync)
	return resp
}

func applyWinACL(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	var resp providers.ApplyResourceChangeResponse
	if req.PlannedState.IsNull() {
		resp.NewState = req.PlannedState
		return resp
	}
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("windows_acl: %w", err))
		return resp
	}
	a, err := winACLFrom(req.PlannedState)
	if err != nil {
		return fail(err)
	}
	h, err := winHost(ctx, req.PlannedState.GetAttr("ssh"))
	if err != nil {
		return fail(err)
	}
	names := windows.Principals(a.Entries, a.Owner)
	s, err := windows.ReadPath(ctx, h.raw(), a.Path, names, false)
	if err != nil {
		return fail(err)
	}
	if s.Kind == "missing" {
		return fail(fmt.Errorf("%s doesn't exist. Create it in an earlier step", a.Path))
	}
	for _, e := range a.Entries {
		if e.Inheritance != "" && e.Inheritance != "none" && s.Kind == "file" {
			return fail(fmt.Errorf("%s is a file, so inheritance can't apply to the rule for %s", a.Path, e.Principal))
		}
	}
	ok, err := winACLMatches(s, a)
	if err != nil {
		return fail(err)
	}
	if !ok {
		if err := windows.ApplyACL(ctx, h.raw(), a, s.Kind == "directory"); err != nil {
			return fail(fmt.Errorf("setting rules on %s: %w", a.Path, err))
		}
		if s, err = windows.ReadPath(ctx, h.raw(), a.Path, names, false); err != nil {
			return fail(err)
		}
		if ok, err = winACLMatches(s, a); err != nil {
			return fail(err)
		}
		if !ok {
			return fail(fmt.Errorf("the rules on %s don't match what was set; something else changed them", a.Path))
		}
	}
	resp.NewState = withSync(req.PlannedState, true)
	return resp
}
