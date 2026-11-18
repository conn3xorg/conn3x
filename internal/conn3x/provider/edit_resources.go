// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules"
	"github.com/opentofu/opentofu/internal/conn3x/modules/edit"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// An edit resource changes part of a file. edits builds the edit from
// configuration; remove builds the edit that undoes it for on_remove.
type editKind struct {
	name   string
	attrs  map[string]*configschema.Attribute
	edit   func(cty.Value) func(string) (string, error)
	remove func(cty.Value) func(string) (string, error)
	check  func(cty.Value) error
	desc   string // what the schema says; a default covers line and block
	// missingOK says a missing file already satisfies this edit. Removing
	// the edit then has nothing to do on a missing file either.
	missingOK func(cty.Value) bool
}

var lineKind = editKind{
	name: "line",
	attrs: map[string]*configschema.Attribute{
		"line":          {Type: cty.String, Optional: true, Description: "The line. Required unless state is \"absent\" with a regexp."},
		"regexp":        {Type: cty.String, Optional: true, Description: "Replace the last line matching this; with state \"absent\", remove every match."},
		"insert_after":  {Type: cty.String, Optional: true, Description: "When adding, insert after the last line matching this regexp, or \"EOF\" (default)."},
		"insert_before": {Type: cty.String, Optional: true, Description: "When adding, insert before the first line matching this regexp, or \"BOF\"."},
		"state":         {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		l := lineFrom(v)
		return func(s string) (string, error) { return edit.ApplyLine(s, l) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		l := lineFrom(v)
		l.State, l.InsertAfter, l.InsertBefore = edit.Absent, "", ""
		if l.Regexp == "" || l.Line != "" {
			l.Regexp = ""
		}
		return func(s string) (string, error) { return edit.ApplyLine(s, l) }
	},
	check: func(v cty.Value) error { return lineFrom(v).Validate() },
}

func lineFrom(v cty.Value) edit.Line {
	return edit.Line{
		Line: stringOr(v.GetAttr("line"), ""), Regexp: stringOr(v.GetAttr("regexp"), ""),
		InsertAfter: stringOr(v.GetAttr("insert_after"), ""), InsertBefore: stringOr(v.GetAttr("insert_before"), ""),
		State: edit.State(stringOr(v.GetAttr("state"), "")),
	}
}

var blockKind = editKind{
	name: "block",
	attrs: map[string]*configschema.Attribute{
		"content":       {Type: cty.String, Optional: true, Description: "Lines of the block."},
		"marker":        {Type: cty.String, Optional: true, Description: "Marker line with {mark}, which becomes BEGIN and END. Defaults to \"# {mark} CONN3X MANAGED BLOCK\"."},
		"insert_after":  {Type: cty.String, Optional: true, Description: "Where a new block goes: after the last match of this regexp, or \"EOF\" (default)."},
		"insert_before": {Type: cty.String, Optional: true, Description: "Where a new block goes: before the first match of this regexp, or \"BOF\"."},
		"state":         {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		b := blockFrom(v)
		return func(s string) (string, error) { return edit.ApplyBlock(s, b) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		b := blockFrom(v)
		b.State = edit.Absent
		return func(s string) (string, error) { return edit.ApplyBlock(s, b) }
	},
	check: func(v cty.Value) error { return blockFrom(v).Validate() },
}

func blockFrom(v cty.Value) edit.Block {
	return edit.Block{
		Content: stringOr(v.GetAttr("content"), ""), Marker: stringOr(v.GetAttr("marker"), ""),
		InsertAfter: stringOr(v.GetAttr("insert_after"), ""), InsertBefore: stringOr(v.GetAttr("insert_before"), ""),
		State: edit.State(stringOr(v.GetAttr("state"), "")),
	}
}

var iniKind = editKind{
	name: "ini",
	desc: "One option in an INI-style file, which should or should not be there. The rest of the file stays as it is.",
	attrs: map[string]*configschema.Attribute{
		"section":         {Type: cty.String, Optional: true, Description: "The section, added when it's missing. Without it, the option goes before the first section."},
		"option":          {Type: cty.String, Required: true, Description: "The option's name."},
		"value":           {Type: cty.String, Optional: true, Description: "The option's value. Required unless state is \"absent\"."},
		"state":           {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
		"no_extra_spaces": {Type: cty.Bool, Optional: true, Description: "Write option=value rather than option = value."},
		"uncomment":       {Type: cty.Bool, Optional: true, Description: "Put the value on a commented-out line for this option, rather than keeping every comment."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		c := iniFrom(v)
		return func(s string) (string, error) { return edit.ApplyINI(s, c) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		c := iniFrom(v)
		c.State = edit.Absent
		return func(s string) (string, error) { return edit.ApplyINI(s, c) }
	},
	check: func(v cty.Value) error {
		c := iniFrom(v)
		if c.State != edit.Absent && v.GetAttr("value").IsNull() {
			return errors.New("value is required unless state is \"absent\"")
		}
		return c.Validate()
	},
	missingOK: func(v cty.Value) bool { return iniFrom(v).State == edit.Absent },
}

func iniFrom(v cty.Value) edit.INI {
	spaces, uncomment := v.GetAttr("no_extra_spaces"), v.GetAttr("uncomment")
	return edit.INI{
		Section: stringOr(v.GetAttr("section"), ""), Option: stringOr(v.GetAttr("option"), ""),
		Value: stringOr(v.GetAttr("value"), ""), State: edit.State(stringOr(v.GetAttr("state"), "")),
		NoExtraSpaces: known(spaces) && spaces.True(), Uncomment: known(uncomment) && uncomment.True(),
	}
}

var xmlValueKind = editKind{
	name: "xml_value",
	desc: "One element's text or one attribute in an XML file, which should or should not be there. The rest of the file stays as it was, byte for byte.",
	attrs: map[string]*configschema.Attribute{
		"xpath": {Type: cty.String, Required: true, Description: "Which element or attribute, from the root: element names with [@attr='value'] or [n] to pick one, ending in /@name for an attribute, such as /Server/Service/Connector[@port='8080']/@protocol. A missing last element is added."},
		"value": {Type: cty.String, Optional: true, Description: "The element's text or the attribute's value, unescaped. Required unless state is \"absent\"."},
		"state": {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\", which takes the attribute or the element out."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		c := xmlValueFrom(v)
		return func(s string) (string, error) { return edit.ApplyXMLValue(s, c) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		c := xmlValueFrom(v)
		c.State = edit.Absent
		return func(s string) (string, error) { return edit.ApplyXMLValue(s, c) }
	},
	check: func(v cty.Value) error {
		c := xmlValueFrom(v)
		if c.State != edit.Absent && v.GetAttr("value").IsNull() {
			return errors.New("value is required unless state is \"absent\"")
		}
		return c.Validate()
	},
	missingOK: func(v cty.Value) bool { return xmlValueFrom(v).State == edit.Absent },
}

func xmlValueFrom(v cty.Value) edit.XMLValue {
	return edit.XMLValue{XPath: stringOr(v.GetAttr("xpath"), ""), Value: stringOr(v.GetAttr("value"), ""), State: edit.State(stringOr(v.GetAttr("state"), ""))}
}

var jsonValueKind = editKind{
	name: "json_value",
	desc: "One value in a JSON file, which should or should not be there. The rest of the file stays as it was, byte for byte.",
	attrs: map[string]*configschema.Attribute{
		"key":   {Type: cty.String, Required: true, Description: "Where the value is: object keys joined by dots, with [n] for an array element, such as server.port or upstreams[0].host. Missing objects on the way are made."},
		"value": {Type: cty.String, Optional: true, Description: "The value, as JSON: write it with jsonencode, such as jsonencode(8080), jsonencode(\"info\") or jsonencode({ enabled = true }). Required unless state is \"absent\". A value that's equal already, however it's written, is left alone."},
		"state": {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\", which takes the key out."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		c := jsonValueFrom(v)
		return func(s string) (string, error) { return edit.ApplyJSONValue(s, c) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		c := jsonValueFrom(v)
		c.State = edit.Absent
		return func(s string) (string, error) { return edit.ApplyJSONValue(s, c) }
	},
	check: func(v cty.Value) error {
		c := jsonValueFrom(v)
		if c.State != edit.Absent && v.GetAttr("value").IsNull() {
			return errors.New("value is required unless state is \"absent\"")
		}
		return c.Validate()
	},
	missingOK: func(v cty.Value) bool { return jsonValueFrom(v).State == edit.Absent },
}

func jsonValueFrom(v cty.Value) edit.JSONValue {
	return edit.JSONValue{Path: stringOr(v.GetAttr("key"), ""), Value: stringOr(v.GetAttr("value"), ""), State: edit.State(stringOr(v.GetAttr("state"), ""))}
}

var limitKind = editKind{
	name: "limit",
	desc: "One PAM limit in a limits.conf file, which should or should not be there. The rest of the file stays as it is.",
	attrs: map[string]*configschema.Attribute{
		"domain": {Type: cty.String, Required: true, Description: "Who the limit applies to: a user, @group, * or a range, as in limits.conf(5)."},
		"type":   {Type: cty.String, Required: true, Description: "\"soft\", \"hard\" or \"-\" for both."},
		"item":   {Type: cty.String, Required: true, Description: "What is limited, such as nofile or nproc."},
		"value":  {Type: cty.String, Optional: true, Description: "The limit: a number, or \"unlimited\", \"infinity\" or \"-1\". Required unless state is \"absent\"."},
		"state":  {Type: cty.String, Optional: true, Description: "\"present\" (default) or \"absent\"."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		l := limitFrom(v)
		return func(s string) (string, error) { return edit.ApplyLimit(s, l) }
	},
	remove: func(v cty.Value) func(string) (string, error) {
		l := limitFrom(v)
		l.State = edit.Absent
		return func(s string) (string, error) { return edit.ApplyLimit(s, l) }
	},
	check:     func(v cty.Value) error { return limitFrom(v).Validate() },
	missingOK: func(v cty.Value) bool { return limitFrom(v).State == edit.Absent },
}

func limitFrom(v cty.Value) edit.Limit {
	return edit.Limit{
		Domain: stringOr(v.GetAttr("domain"), ""), Type: stringOr(v.GetAttr("type"), ""), Item: stringOr(v.GetAttr("item"), ""),
		Value: stringOr(v.GetAttr("value"), ""), State: edit.State(stringOr(v.GetAttr("state"), "")),
	}
}

var replaceKind = editKind{
	name: "replace",
	desc: "Every match of a regexp in a file, replaced. The file must already exist.",
	attrs: map[string]*configschema.Attribute{
		"regexp":  {Type: cty.String, Required: true, Description: "What to look for. ^ and $ match at each line, and . doesn't match a line break."},
		"replace": {Type: cty.String, Required: true, Description: "What to put in its place, which can use $1, ${1} and ${name}. Write $$ for a dollar sign. An empty string deletes each match."},
	},
	edit: func(v cty.Value) func(string) (string, error) {
		r := replaceFrom(v)
		return func(s string) (string, error) { return edit.ApplyReplace(s, r) }
	},
	// The old text is gone, so there is nothing to put back.
	remove: func(cty.Value) func(string) (string, error) {
		return func(s string) (string, error) { return s, nil }
	},
	check: func(v cty.Value) error {
		if c := v.GetAttr("create"); known(c) && c.True() {
			return errors.New("create doesn't apply here: a new file has nothing to replace")
		}
		if v.GetAttr("on_remove").RawEquals(cty.StringVal(onRemoveDelete)) {
			return errors.New("on_remove can't be \"delete\": a replacement can't be undone")
		}
		return replaceFrom(v).Validate()
	},
}

func replaceFrom(v cty.Value) edit.Replace {
	return edit.Replace{Regexp: stringOr(v.GetAttr("regexp"), ""), With: stringOr(v.GetAttr("replace"), "")}
}

func (k editKind) schema() providers.Schema {
	attrs := map[string]*configschema.Attribute{
		"id":        {Type: cty.String, Computed: true},
		"revision":  revisionAttr(),
		"path":      {Type: cty.String, Required: true, Description: "Absolute path of the file."},
		"create":    {Type: cty.Bool, Optional: true, Description: "Create the file when it is missing. Otherwise a missing file is an error."},
		"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "\"forget\" (default) leaves the file as it is, \"delete\" takes the edit back out."},
		"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the file already matches."},
		"mode":      {Type: cty.String, Optional: true, Description: "The file's mode, such as \"0644\", set with the edit. Unset keeps the mode the file has, or 0644 for a file it creates."},
		"owner":     {Type: cty.String, Optional: true, Description: "The file's owner, set with the edit. Unset keeps the owner the file has."},
		"group":     {Type: cty.String, Optional: true, Description: "The file's group, set with the edit. Unset keeps the group the file has."},
		"backup": {
			Type: cty.Bool, Optional: true,
			Description: "true copies the file, before an edit changes it, beside itself with .conn3x-, the time in UTC, a number and a ~ after its name, such as job.conn3x-20261118T130501Z.4127~, keeping its mode and owner. The ~ keeps cron.d, logrotate.d and the like from loading the copy. An apply that changes nothing makes no copy. Old copies stay until you remove them.",
		},
		"backup_keep": {
			Type: cty.Number, Optional: true,
			Description: "With backup, keeps only this many of the newest copies, removing older ones each time a new one is made. Unset keeps them all.",
		},
		"validate": {
			Type: cty.String, Optional: true, WriteOnly: true,
			Description: "A command that checks the edited file before it replaces the old one, such as \"sshd -t -f %s\". %s stands for the temporary file. Runs only when the edit changes the file, and is kept out of state.",
		},
	}
	for name, a := range k.attrs {
		attrs[name] = a
	}
	desc := k.desc
	if desc == "" {
		desc = "Part of a text file: a " + k.name + " that should, or should not, be there."
	}
	return providers.Schema{Block: &configschema.Block{
		Description: desc,
		Attributes:  attrs,
		BlockTypes:  map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func (k editKind) validate(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := (file.Desired{Path: cfg.GetAttr("path").AsString(), Mode: "0644"}).Validate(); err != nil {
		diags = diags.Append(attrError("path", err.Error()))
	}
	if err := k.check(cfg); err != nil {
		diags = diags.Append(attrError(k.name, err.Error()))
	}
	if m := cfg.GetAttr("mode"); !m.IsNull() {
		if err := (file.Desired{Path: "/", Mode: m.AsString()}).Validate(); err != nil {
			diags = diags.Append(attrError("mode", err.Error()))
		}
	}
	if v := cfg.GetAttr("validate"); !v.IsNull() {
		if err := (file.Desired{Path: "/", Mode: "0644", ValidateCommand: v.AsString()}).Validate(); err != nil {
			diags = diags.Append(attrError("validate", err.Error()))
		}
	}
	if err := validateBackupKeep(cfg); err != nil {
		diags = diags.Append(attrError("backup_keep", err.Error()))
	}
	return diags
}

func (k editKind) plan(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	resp := planPathResource(req, k.name, func(map[string]cty.Value) {})
	if resp.PlannedState.IsNull() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	changed := req.PriorState.IsNull()
	if !changed {
		for _, name := range append(slices.Collect(maps.Keys(k.attrs)), "mode", "owner", "group") {
			if !req.PriorState.GetAttr(name).RawEquals(vals[name]) {
				changed = true
			}
		}
		if s := req.PriorState.GetAttr("in_sync"); !known(s) || s.False() {
			changed = true
		}
	}
	if changed {
		vals["in_sync"] = cty.UnknownVal(cty.Bool)
	} else {
		vals["in_sync"] = cty.True
	}
	vals["validate"] = cty.NullVal(cty.String) // write-only, so adding it never shows a diff
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

func (k editKind) read(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		vals := prior.AsValueMap()
		actual, err := file.Read(ctx, h, prior.GetAttr("path").AsString())
		if err != nil {
			return cty.NilVal, err
		}
		inSync := false
		if actual.Exists {
			edited, err := k.edit(prior)(actual.Content)
			if err != nil {
				return cty.NilVal, err
			}
			inSync = !file.NeedsChange(wanted(prior, actual, edited), actual)
		} else if k.missingOK != nil {
			inSync = k.missingOK(prior)
		}
		vals["in_sync"] = cty.BoolVal(inSync)
		return cty.ObjectVal(vals), nil
	})
}

func (k editKind) apply(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			vals := planned.AsValueMap()
			vals["in_sync"] = cty.True
			if k.missingOK != nil && k.missingOK(planned) {
				if actual, err := file.Read(ctx, h, planned.GetAttr("path").AsString()); err != nil {
					return cty.NilVal, err
				} else if !actual.Exists {
					return cty.ObjectVal(vals), nil
				}
			}
			path := planned.GetAttr("path").AsString()
			target, err := editTarget(ctx, h, path)
			if err != nil {
				return cty.NilVal, err
			}
			create := planned.GetAttr("create")
			want := fileAttrs(planned)
			want.ValidateCommand = stringOr(req.Config.GetAttr("validate"), "")
			if err := editFile(ctx, h, target, path, known(create) && create.True(), want, k.edit(planned)); err != nil {
				return cty.NilVal, err
			}
			return cty.ObjectVal(vals), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			if k.missingOK != nil {
				if actual, err := file.Read(ctx, h, prior.GetAttr("path").AsString()); err != nil {
					return err
				} else if !actual.Exists {
					return nil
				}
			}
			path := prior.GetAttr("path").AsString()
			target, err := editTarget(ctx, h, path)
			if err != nil {
				return err
			}
			// The config, and so validate, is gone when the step is removed.
			return editFile(ctx, h, target, path, false, fileAttrs(prior), k.remove(prior))
		})
}

// editTarget is the file to write: what path links to, if it's a link. Going
// through the link keeps the link, and writes with the target's mode and owner
// rather than the link's own 0777. It also keys editFile's lock, so edits
// through a link and edits to the file itself take turns. A link it can't
// resolve is an error, so editFile never sees the link itself.
func editTarget(ctx context.Context, h *hostConn, path string) (string, error) {
	q := ssh.Quote(path)
	// Run as a user, the answer only stands if that user can write there:
	// the edit that follows acts on the answer, on its own route. Run as
	// root, a path missing where anyone can create it is its own answer:
	// a link that turns up there later isn't one to follow.
	res, err := h.Run(ctx, modules.Guard(modules.Settled+`route_settled `+q+` || exit 0
r=$(readlink -f -- `+q+` 2>/dev/null) || { ! test -L `+q+`; exit; }
if [ -n "$CONN3X_ROUTE_USER" ] && [ -n "$r" ]; then
  if [ -e "$r" ]; then test -w "$r"; else test -w "$(dirname -- "$r")"; fi || {
    if [ -L `+q+` ]; then echo `+q+`" leads to $r, which $CONN3X_ROUTE_USER can't write" >&2
    else echo `+q+`" can't be written by $CONN3X_ROUTE_USER; give the file to $CONN3X_ROUTE_USER first" >&2; fi
    exit 1
  }
fi
printf '%s\n' "$r"`, modules.Follow(path)), nil)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		if msg := strings.TrimSpace(string(res.Stderr)); msg != "" {
			return "", errors.New(msg)
		}
		return "", fmt.Errorf("%s is a symlink that can't be followed", path)
	}
	// Only readlink's own newline goes: a path can end in a space.
	if real := strings.TrimSuffix(string(res.Stdout), "\n"); real != "" {
		return real, nil
	}
	return path, nil // readlink fails on a path whose directory isn't there yet
}

// editFile reads a file, applies fn and writes it back only if it changed,
// keeping its mode and ownership. Edits to one file on a host take turns,
// so one doesn't write over another it read the file before.
//
// via is the path as the step gives it, which editTarget turned into path.
// Where someone else owns the way to via, editTarget's answer came from a
// process of theirs, which they can make say anything. So the edit goes the
// same way: as them, whatever file the answer names.
func editFile(ctx context.Context, h *hostConn, path, via string, create bool, want file.Desired, fn func(string) (string, error)) error {
	defer lockHost(h, "edit\x00"+path)()
	var routes []modules.Route
	if via != path {
		routes = append(routes, modules.Follow(via))
	}
	actual, err := file.Read(ctx, h, path, routes...)
	if err != nil {
		return err
	}
	if !actual.Exists {
		if !create {
			return fmt.Errorf("%s does not exist; set create = true to create it", path)
		}
		actual = file.Actual{Mode: "0644"}
	}
	edited, err := fn(actual.Content)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	d := want
	d.Path, d.Content = path, edited
	d = withActual(d, actual)
	if actual.Exists && !file.NeedsChange(d, actual) {
		return nil
	}
	return file.Apply(ctx, h, d, routes...)
}

// fileAttrs is the mode, owner and group an edit step sets, empty where it
// leaves the file's own.
func fileAttrs(v cty.Value) file.Desired {
	b := v.GetAttr("backup")
	return file.Desired{Mode: stringOr(v.GetAttr("mode"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Group: stringOr(v.GetAttr("group"), ""), Backup: known(b) && b.True(), BackupKeep: backupKeep(v)}
}

// backupKeep is a step's backup_keep, or 0 when it's unset.
func backupKeep(v cty.Value) int {
	k := v.GetAttr("backup_keep")
	if !known(k) {
		return 0
	}
	n, _ := k.AsBigFloat().Int64()
	return int(n)
}

// validateBackupKeep refuses a backup_keep below 1, or one without backup.
func validateBackupKeep(cfg cty.Value) error {
	k := cfg.GetAttr("backup_keep")
	if k.IsNull() || !k.IsKnown() {
		return nil
	}
	if n, acc := k.AsBigFloat().Int64(); acc != big.Exact || n < 1 {
		return errors.New("backup_keep must be a whole number from 1")
	}
	if b := cfg.GetAttr("backup"); b.IsKnown() && (b.IsNull() || b.False()) {
		return errors.New("backup_keep needs backup = true")
	}
	return nil
}

// withActual fills what d leaves unset from the file as it is.
func withActual(d file.Desired, a file.Actual) file.Desired {
	if d.Mode == "" {
		d.Mode = a.Mode
	}
	if d.Owner == "" {
		d.Owner = a.Owner
	}
	if d.Group == "" {
		d.Group = a.Group
	}
	return d
}

// wanted is the file an edit step v wants, given it as it is and its
// content edited.
func wanted(v cty.Value, a file.Actual, edited string) file.Desired {
	d := fileAttrs(v)
	d.Content = edited
	return withActual(d, a)
}
