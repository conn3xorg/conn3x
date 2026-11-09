// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/conn3x/importid"
	"github.com/opentofu/opentofu/internal/conn3x/modules/file"
	"github.com/opentofu/opentofu/internal/conn3x/modules/firewall"
	"github.com/opentofu/opentofu/internal/conn3x/modules/mount"
	"github.com/opentofu/opentofu/internal/conn3x/modules/pkg"
	"github.com/opentofu/opentofu/internal/conn3x/modules/postgresql"
	"github.com/opentofu/opentofu/internal/conn3x/modules/selinux"
	"github.com/opentofu/opentofu/internal/conn3x/modules/service"
	"github.com/opentofu/opentofu/internal/conn3x/modules/sshkey"
	"github.com/opentofu/opentofu/internal/conn3x/transport/ssh"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

// A step with import = true adopts what is already on a host. The circuit
// lowering writes an import block whose ID is JSON (see conn3x_import.go in
// internal/configs):
//
//	{"v":1,"key":"web1","ssh":{...},"args":{"path":"/etc/motd"},"write_only":true}
//
// ssh says how to reach the host, args are the step's own arguments except
// content, and write_only says the content goes to content_wo, so the
// import must keep it out of state too.

const importVersion = importid.Version

type importID struct {
	V         int                        `json:"v"`
	Key       string                     `json:"key"`
	SSH       json.RawMessage            `json:"ssh"`
	Args      map[string]json.RawMessage `json:"args"`
	WriteOnly bool                       `json:"write_only"`
}

// importable maps each resource type a step can adopt to what names the
// object in its id, and how to tell whether the host has it after a read.
// A resource whose read reports only in_sync can't tell a missing object
// from a different one, so it asks the host with probe before the read.
var importable = map[string]struct {
	id     func(state cty.Value) []string
	exists func(read cty.Value) bool
	what   string
	probe  func(ctx context.Context, h *hostConn, prior cty.Value) (bool, error)
}{
	"conn3x_file":      {pathID(""), notNull, "file %s", nil},
	"conn3x_directory": {pathID("directory"), notNull, "directory %s", nil},
	"conn3x_link":      {pathID("link"), notNull, "link %s", nil},
	"conn3x_package":   {nameID("package", nil), observed("installed_version"), "package %s", nil},
	"conn3x_service":   {nameID("service", service.Unit), observed("running"), "service %s", nil},
	"conn3x_user":      {nameID("user", nil), observed("uid"), "user %s", nil},
	"conn3x_group":     {nameID("group", nil), observed("gid"), "group %s", nil},

	"conn3x_authorized_key": {authorizedKeyID, notNull, "the key in %s's authorized_keys", hasAuthorizedKey},
	"conn3x_cron":           {nameID("cron", nil), notNull, "cron job %s", hasCron},
	"conn3x_timer":          {nameID("timer", nil), notNull, "timer %s", hasTimer},
	"conn3x_sysctl":         {nameID("sysctl", nil), notNull, "kernel parameter %s", hasSysctl},
	"conn3x_mount":          {pathID("mount"), notNull, "mount %s", hasMount},
	"conn3x_repository":     {nameID("repository", nil), notNull, "repository %s", hasRepository},

	"conn3x_postgresql_database": {nameID("postgresql_database", nil), notNull, "PostgreSQL database %s", hasPgDatabase},
	"conn3x_postgresql_role":     {nameID("postgresql_role", nil), notNull, "PostgreSQL role %s", hasPgRole},

	"conn3x_windows_file":           {pathID(""), notNull, "file %s", nil},
	"conn3x_windows_directory":      {pathID("windows_directory"), notNull, "directory %s", nil},
	"conn3x_windows_service":        {nameID("windows_service", nil), notNull, "service %s", hasWinService},
	"conn3x_windows_registry_value": {keysID("windows_registry_value", "key", "name"), notNull, "registry value %s", hasWinRegistry},
	"conn3x_windows_feature":        {nameID("windows_feature", nil), notNull, "feature %s", hasWinFeature},
	"conn3x_windows_user":           {nameID("windows_user", nil), notNull, "local user %s", hasWinUser},
	"conn3x_windows_group":          {nameID("windows_group", nil), notNull, "local group %s", hasWinGroup},
	"conn3x_windows_package":        {keysID("windows_package", "product_code"), notNull, "MSI package %s", hasWinPackage},

	// A host always has a hostname, time zone and locale, so there's
	// nothing to find first: a different one imports and plans an update.
	"conn3x_hostname": {singleID("hostname"), notNull, "%s", nil},
	"conn3x_timezone": {singleID("timezone"), notNull, "%s", nil},
	"conn3x_locale":   {singleID("locale"), notNull, "%s", nil},

	// A rule's id is all its fields, as planRule writes it.
	"conn3x_firewalld":        {keysID("firewalld", "zone", "service", "port"), notNull, "", hasFirewalld},
	"conn3x_ufw_rule":         {keysID("ufw", "action", "port", "from"), notNull, "", hasUFWRule},
	"conn3x_selinux_boolean":  {keysID("selinux_boolean", "name"), notNull, "SELinux boolean %s", hasSELinuxBoolean},
	"conn3x_selinux_fcontext": {keysID("selinux_fcontext", "target"), notNull, "a local SELinux file context for %s", hasFcontext},
}

// importDeletes are the types whose on_remove defaults to delete at plan
// time (deleteByDefault), so an import must default it the same way.
var importDeletes = map[string]bool{"conn3x_authorized_key": true, "conn3x_cron": true, "conn3x_timer": true, "conn3x_firewalld": true, "conn3x_ufw_rule": true}

// ruleWhat says which rule a missing-object error is about, since no one
// part of a rule's id names it.
var ruleWhat = map[string]func(cty.Value) string{
	"conn3x_firewalld": func(v cty.Value) string {
		what := "the firewalld rule allowing " + stringOr(v.GetAttr("service"), "") + stringOr(v.GetAttr("port"), "")
		if z := stringOr(v.GetAttr("zone"), ""); z != "" {
			what += " in zone " + z
		}
		return what
	},
	"conn3x_ufw_rule": func(v cty.Value) string {
		what := "the ufw rule " + v.GetAttr("action").AsString() + " " + v.GetAttr("port").AsString()
		if from := stringOr(v.GetAttr("from"), ""); from != "" {
			what += " from " + from
		}
		return what
	},
}

// keysID is the id planSynced writes for these key attributes.
func keysID(kind string, keys ...string) func(cty.Value) []string {
	return func(v cty.Value) []string {
		id := []string{kind}
		for _, k := range keys {
			id = append(id, keyString(v.GetAttr(k)))
		}
		return id
	}
}

// hasFirewalld: the running or the permanent firewall allows it; allowed
// in only one, it imports and plans an update.
func hasFirewalld(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	runtime, permanent, err := firewall.ReadFirewalld(ctx, h, firewalldFrom(v))
	return runtime || permanent, err
}

func hasUFWRule(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	return firewall.ReadUFW(ctx, h, ufwRuleFrom(v))
}

// hasSELinuxBoolean: the policy has the boolean. With SELinux off there is
// no /sys/fs/selinux, and the read that follows says so.
func hasSELinuxBoolean(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	f := "/sys/fs/selinux/booleans/" + v.GetAttr("name").AsString()
	res, err := h.Run(ctx, "test ! -d /sys/fs/selinux || test -e "+ssh.Quote(f), nil)
	return err == nil && res.ExitCode == 0, err
}

func hasFcontext(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	ty, err := selinux.ReadFcontext(ctx, h, fcontextFrom(v))
	return ty != "", err
}

// singleID names one-per-host settings by kind alone, as planSynced does
// with no keys.
func singleID(kind string) func(cty.Value) []string {
	return func(cty.Value) []string { return []string{kind} }
}

func authorizedKeyID(v cty.Value) []string {
	return []string{"authorized_key", v.GetAttr("user").AsString()}
}

// hasAuthorizedKey: the user exists and the key is already in the file.
func hasAuthorizedKey(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	loc, err := sshkey.Locate(ctx, h, v.GetAttr("user").AsString())
	if err != nil {
		return false, nil // no such user, as readAuthorizedKey treats it
	}
	content, err := sshkey.Read(ctx, h, loc)
	if err != nil {
		return false, err
	}
	edited, err := sshkey.Edit(content, v.GetAttr("key").AsString(), true)
	return err == nil && edited == content, err
}

func hasCron(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	a, err := file.Read(ctx, h, cronFrom(v).Path())
	return a.Exists, err
}

func hasTimer(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	u, err := service.Read(ctx, h, v.GetAttr("name").AsString()+".timer")
	return u.Exists, err
}

// hasSysctl: the kernel has the parameter. Its value and drop-in file are
// what the step then manages, so a different value plans a change.
func hasSysctl(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	res, err := h.Run(ctx, "sysctl -n -- "+ssh.Quote(v.GetAttr("name").AsString()), nil)
	return err == nil && res.ExitCode == 0, err
}

// hasPgDatabase: the server has a database of that name. Its owner and
// encoding are what the step then manages. Reading it runs psql as the
// postgres user, so it needs become = true, and says so without it.
func hasPgDatabase(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	s, err := postgresql.ReadDatabase(ctx, h, v.GetAttr("name").AsString())
	return s.Exists, err
}

// hasPgRole: the server has a role of that name. Its password stays as it
// is: password_wo never goes into an import ID, so the role keeps the one
// it has until a step sets one.
func hasPgRole(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	s, err := postgresql.ReadRole(ctx, h, v.GetAttr("name").AsString())
	return s.Exists, err
}

// hasMount: fstab has an entry for the path, or something is mounted there.
func hasMount(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	a, err := mount.Read(ctx, h, mountFrom(v))
	return a.Entry != "" || a.Mounted, err
}

// hasRepository: any of the repository's files is there.
func hasRepository(ctx context.Context, h *hostConn, v cty.Value) (bool, error) {
	family, err := pkg.DetectFamily(ctx, h)
	if err != nil {
		return false, err
	}
	for path := range repoFrom(v).Files(family) {
		a, err := file.Read(ctx, h, path)
		if err != nil || a.Exists {
			return a.Exists, err
		}
	}
	return false, nil
}

func pathID(kind string) func(cty.Value) []string {
	return func(v cty.Value) []string {
		if kind == "" {
			return []string{v.GetAttr("path").AsString()}
		}
		return []string{kind, v.GetAttr("path").AsString()}
	}
}

func nameID(kind string, norm func(string) string) func(cty.Value) []string {
	return func(v cty.Value) []string {
		name := v.GetAttr("name").AsString()
		if norm != nil {
			name = norm(name)
		}
		return []string{kind, name}
	}
}

func notNull(v cty.Value) bool { return !v.IsNull() }

func observed(attr string) func(cty.Value) bool {
	return func(v cty.Value) bool { return !v.IsNull() && !v.GetAttr(attr).IsNull() }
}

func (p *Provider) ImportResourceState(ctx context.Context, req providers.ImportResourceStateRequest) providers.ImportResourceStateResponse {
	var resp providers.ImportResourceStateResponse
	state, key, what, diags := p.readExisting(ctx, req.TypeName, req.Target.ID)
	resp.Diagnostics = diags
	if what != "" {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.Sourceless(tfdiags.Error,
			fmt.Sprintf("Nothing to import on %s", key),
			fmt.Sprintf("The step imports %s on %s, but %s doesn't have it, so there's nothing to adopt. "+
				"Remove %s from the step's import, or set import to the hosts that already have it; "+
				"Conn3x then creates it on the rest.", what, key, key, key)))
	}
	if resp.Diagnostics.HasErrors() {
		return resp
	}
	resp.ImportedResources = []providers.ImportedResource{{TypeName: req.TypeName, State: state}}
	return resp
}

// ReadExisting reads what an import ID names on its host, the way an import
// does, for conn3x generate step: the state an import would adopt, or an
// error naming what the host doesn't have.
func ReadExisting(ctx context.Context, typeName, rawID string) (cty.Value, error) {
	state, key, what, diags := (&Provider{}).readExisting(ctx, typeName, rawID)
	if what != "" {
		return cty.NilVal, fmt.Errorf("%s doesn't have %s", key, what)
	}
	if err := diags.Err(); err != nil {
		return cty.NilVal, err
	}
	return state, nil
}

// readExisting reads the object an import ID names. When the host doesn't
// have it, what describes the object and the state is empty.
func (p *Provider) readExisting(ctx context.Context, typeName, rawID string) (state cty.Value, key, what string, diags tfdiags.Diagnostics) {
	kind, ok := importable[typeName]
	if !ok {
		return cty.NilVal, "", "", unsupported("importing " + typeName)
	}
	id, prior, err := importPrior(typeName, rawID)
	if err != nil {
		return cty.NilVal, "", "", diags.Append(tfdiags.Sourceless(tfdiags.Error, "Invalid import ID", err.Error()))
	}
	missing := func() (cty.Value, string, string, tfdiags.Diagnostics) {
		if describe, ok := ruleWhat[typeName]; ok {
			return cty.NilVal, id.Key, describe(prior), diags
		}
		return cty.NilVal, id.Key, fmt.Sprintf(kind.what, kind.id(prior)[len(kind.id(prior))-1]), diags
	}

	// Read here rather than leave it to the refresh that follows, so a
	// missing object gets an error that says what to do about it.
	ctx, done := p.withStop(ctx)
	defer done()
	if kind.probe != nil {
		h, err := dialConnection(ctx, prior.GetAttr("ssh"))
		if err != nil {
			return cty.NilVal, id.Key, "", diags.Append(attrError("ssh", err.Error()))
		}
		found, err := kind.probe(ctx, h, prior)
		if err != nil {
			return cty.NilVal, id.Key, "", diags.Append(err)
		}
		if !found {
			return missing()
		}
	}
	read := resourceTypes[typeName].read(ctx, providers.ReadResourceRequest{TypeName: typeName, PriorState: prior})
	diags = diags.Append(read.Diagnostics)
	if diags.HasErrors() {
		return cty.NilVal, id.Key, "", diags
	}
	if !kind.exists(read.NewState) {
		return missing()
	}
	state = adopted(typeName, read.NewState)
	if fill, ok := importFill[typeName]; ok {
		h, err := dialConnection(ctx, prior.GetAttr("ssh"))
		if err == nil {
			state, err = fill(ctx, h, state)
		}
		if err != nil {
			return cty.NilVal, id.Key, "", diags.Append(err)
		}
	}
	return state, id.Key, "", diags
}

// importPrior decodes an import ID into the state a read starts from.
func importPrior(typeName, raw string) (importID, cty.Value, error) {
	var id importID
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&id); err != nil {
		return id, cty.NilVal, fmt.Errorf("a step's import ID is JSON written by the circuit, and this one doesn't read: %w", err)
	}
	if id.V != importVersion {
		return id, cty.NilVal, fmt.Errorf("import ID version %d isn't one this Conn3x reads (it reads %d); was it written by a newer Conn3x?", id.V, importVersion)
	}
	if id.Key == "" || len(id.SSH) == 0 {
		return id, cty.NilVal, fmt.Errorf("import ID needs key and ssh")
	}
	attrs := map[string]json.RawMessage{"ssh": id.SSH}
	for k, v := range id.Args {
		if k == "ssh" || importid.LeftOut(k) {
			return id, cty.NilVal, fmt.Errorf("import ID args can't hold %s", k)
		}
		attrs[k] = v
	}
	b, err := json.Marshal(attrs)
	if err != nil {
		return id, cty.NilVal, err
	}
	ty := resourceTypes[typeName].schema().Block.ImpliedType()
	// Attributes left out decode as null; an unknown one is an error.
	v, err := ctyjson.Unmarshal(b, ty)
	if err != nil {
		return id, cty.NilVal, fmt.Errorf("import ID for %s: %w", typeName, err)
	}
	// The step always sets its required arguments; reads and ids rely on them.
	var missing []string
	for name, a := range resourceTypes[typeName].schema().Block.Attributes {
		if a.Required && !importid.LeftOut(name) && v.GetAttr(name).IsNull() {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return id, cty.NilVal, fmt.Errorf("import ID for %s has no %s", typeName, strings.Join(missing, " or "))
	}
	if v.GetAttr("ssh").GetAttr("host").IsNull() {
		return id, cty.NilVal, fmt.Errorf("import ID has no ssh host")
	}
	vals := v.AsValueMap()
	if ty.HasAttribute("on_remove") && vals["on_remove"].IsNull() {
		vals["on_remove"] = cty.StringVal(defaultOnRemove)
		if importDeletes[typeName] {
			vals["on_remove"] = cty.StringVal(onRemoveDelete)
		}
	}
	if typeName == "conn3x_package" && vals["state"].IsNull() {
		vals["state"] = cty.StringVal(string(pkg.Present)) // what planPackage defaults it to
	}
	if id.WriteOnly {
		if typeName == "conn3x_windows_file" {
			return id, cty.NilVal, fmt.Errorf("a windows_file step with content_wo can't import yet; import it with content, or leave import off and let the step write it")
		}
		if typeName != "conn3x_file" {
			return id, cty.NilVal, fmt.Errorf("write_only applies to files only")
		}
		// Make sure there is a key: the read hashes the content with it,
		// so the content itself never reaches state.
		if _, err := hmacKey(true); err != nil {
			return id, cty.NilVal, err
		}
		vals["content_hmac"] = cty.UnknownVal(cty.String)
	}
	vals["id"] = cty.StringVal(strings.Join(append([]string{hostPort(vals["ssh"])}, importable[typeName].id(cty.ObjectVal(vals))...), ":"))
	return id, cty.ObjectVal(vals), nil
}

// adopted is a freshly read object with the arguments the step sets but a
// read doesn't fill taken from the host, so a plan shows how the host
// differs from the step rather than how the step differs from nothing.
func adopted(typeName string, read cty.Value) cty.Value {
	if typeName != "conn3x_service" {
		return read
	}
	vals := read.AsValueMap()
	if !vals["state"].IsNull() {
		vals["state"] = cty.StringVal(string(service.Stopped))
		if vals["running"].True() {
			vals["state"] = cty.StringVal(string(service.Started))
		}
	}
	if !vals["enabled"].IsNull() {
		vals["enabled"] = vals["is_enabled"]
	}
	return cty.ObjectVal(vals)
}
