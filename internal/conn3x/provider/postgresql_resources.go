// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/postgresql"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func pgDatabaseSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A database in the PostgreSQL server on the host, managed through psql as the postgres user. Settings left unset are left as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "Database name, up to 63 bytes. Renaming makes a new database; the old one stays unless on_remove is \"delete\"."},
			"owner":     {Type: cty.String, Optional: true, Description: "Role that owns it. The role has to exist, so make it in an earlier postgresql_role step."},
			"encoding":  {Type: cty.String, Optional: true, Description: "Character encoding for a new database, such as UTF8. PostgreSQL can't change it later, so a database with another one fails the apply."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the database, \"delete\" drops it and everything in it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the database matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func pgDatabaseFrom(v cty.Value) postgresql.Database {
	return postgresql.Database{Name: stringOr(v.GetAttr("name"), ""), Owner: stringOr(v.GetAttr("owner"), ""), Encoding: stringOr(v.GetAttr("encoding"), "")}
}

func validatePgDatabase(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := pgDatabaseFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planPgDatabase(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "postgresql_database", []string{"name"}, []string{"owner", "encoding"})
}

func readPgDatabase(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		d := pgDatabaseFrom(prior)
		s, err := postgresql.ReadDatabase(ctx, h, d.Name)
		if err != nil {
			return cty.NilVal, fmt.Errorf("postgresql_database %s: %w", d.Name, err)
		}
		return withSync(prior, d.Matches(s)), nil
	})
}

func applyPgDatabase(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			d := pgDatabaseFrom(planned)
			if err := postgresql.ApplyDatabase(ctx, h, d); err != nil {
				return cty.NilVal, fmt.Errorf("postgresql_database %s: %w", d.Name, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			name := stringOr(prior.GetAttr("name"), "")
			if err := postgresql.DropDatabase(ctx, h, name); err != nil {
				return fmt.Errorf("postgresql_database %s: %w", name, err)
			}
			return nil
		})
}

func pgRoleSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A role in the PostgreSQL server on the host, such as an application's login, managed through psql as the postgres user.",
		Attributes: map[string]*configschema.Attribute{
			"id":         {Type: cty.String, Computed: true},
			"revision":   revisionAttr(),
			"name":       {Type: cty.String, Required: true, Description: "Role name, up to 63 bytes."},
			"login":      {Type: cty.Bool, Optional: true, Description: "Whether the role can log in. Default true, as for a user; false makes a group role."},
			"attributes": {Type: cty.Set(cty.String), Optional: true, Description: "Exactly the attributes the role has, from SUPERUSER, CREATEDB, CREATEROLE, REPLICATION and BYPASSRLS; those not listed are taken away. Unset leaves them as they are, and a new role gets none."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Password, kept out of plan and state: state records only password_hmac. Conn3x hashes it into a SCRAM-SHA-256 verifier before it leaves this machine, so the plain text never reaches the host or its logs. It's set when the role is made and whenever this value changes. Printable ASCII only. A password changed on the server isn't detected.",
			},
			"password_hmac":   {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of password_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null without password_wo."},
			"database_grants": {Type: cty.Map(cty.Set(cty.String)), Optional: true, Description: "Exactly the role's database privileges, by database, from CONNECT, CREATE and TEMPORARY, such as { app = [\"CONNECT\"] }. A database not listed loses the role's privileges on it. Grants to PUBLIC aren't touched. Unset leaves them as they are."},
			"schema_grants":   {Type: cty.Map(cty.Set(cty.String)), Optional: true, Description: "Exactly the role's privileges on schemas, from USAGE and CREATE, keyed database.schema, such as { \"app.public\" = [\"USAGE\"] }. With table_grants, whole-list in the databases either names: a schema there not listed loses the role's privileges. Other databases aren't read."},
			"table_grants":    {Type: cty.Map(cty.Set(cty.String)), Optional: true, Description: "Exactly the role's privileges on every table in a schema, keyed database.schema, from SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES and TRIGGER, for the tables there now and, by default privileges, those tables_created_by makes later."},
			"tables_created_by": {
				Type: cty.Map(cty.String), Optional: true, Computed: true,
				Description: "Whose new tables get table_grants' privileges by default, keyed database.schema. Unset, it's the schema's owner when the step first grants there, and the plan shows it.",
			},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the role, \"delete\" drops it, which PostgreSQL refuses while it owns anything."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the role matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func pgRoleFrom(v cty.Value) postgresql.Role {
	r := postgresql.Role{Name: stringOr(v.GetAttr("name"), ""), Login: true}
	if l := v.GetAttr("login"); known(l) {
		r.Login = l.True()
	}
	if a := v.GetAttr("attributes"); known(a) {
		r.Attributes = []string{}
		for _, e := range a.AsValueSlice() {
			r.Attributes = append(r.Attributes, e.AsString())
		}
		slices.Sort(r.Attributes)
	}
	return r
}

// stringSetMap reads a map of sets of strings; nil when it's null.
func stringSetMap(v cty.Value) map[string][]string {
	if !known(v) {
		return nil
	}
	out := map[string][]string{}
	for k, set := range v.AsValueMap() {
		out[k] = []string{}
		if known(set) {
			for _, e := range set.AsValueSlice() {
				out[k] = append(out[k], e.AsString())
			}
		}
	}
	return out
}

// pgGrantsFrom reads the grants a role step lists. schema_grants and
// table_grants together are the whole list in the databases they name,
// so either set makes it whole-list there; tables_created_by comes from
// state, where apply resolved it, or the configuration.
func pgGrantsFrom(v cty.Value) postgresql.Grants {
	g := postgresql.Grants{Databases: stringSetMap(v.GetAttr("database_grants"))}
	schemas, tables := stringSetMap(v.GetAttr("schema_grants")), stringSetMap(v.GetAttr("table_grants"))
	if schemas == nil && tables == nil {
		return g
	}
	// An element apply hasn't resolved yet stays empty: the schema's owner.
	creators := map[string]string{}
	if c := v.GetAttr("tables_created_by"); c.IsKnown() && !c.IsNull() {
		for k, e := range c.AsValueMap() {
			if known(e) {
				creators[k] = e.AsString()
			}
		}
	}
	g.Schemas = map[string]postgresql.SchemaGrant{}
	for k, ps := range schemas {
		g.Schemas[k] = postgresql.SchemaGrant{Schema: ps, Tables: tables[k], CreatedBy: creators[k]}
	}
	for k, ps := range tables {
		if _, ok := g.Schemas[k]; !ok {
			g.Schemas[k] = postgresql.SchemaGrant{Tables: ps, CreatedBy: creators[k]}
		}
	}
	return g
}

func validatePgRole(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if pw := cfg.GetAttr("password_wo"); known(pw) {
		if _, err := postgresql.Verifier(pw.AsString()); err != nil || pw.AsString() == "" {
			msg := "password_wo must not be empty"
			if err != nil {
				msg = err.Error()
			}
			diags = diags.Append(attrError("password_wo", msg))
		}
	}
	for _, a := range []string{"name", "login", "attributes", "on_remove"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := pgRoleFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	grants := []string{"database_grants", "schema_grants", "table_grants", "tables_created_by"}
	if slices.IndexFunc(grants, func(a string) bool { return !cfg.GetAttr(a).IsWhollyKnown() }) < 0 {
		if err := pgGrantsFrom(cfg).Validate(); err != nil {
			diags = diags.Append(attrError("database_grants", err.Error()))
		}
		if c := cfg.GetAttr("tables_created_by"); !c.IsNull() {
			tables := cfg.GetAttr("table_grants")
			for k := range c.AsValueMap() {
				if tables.IsNull() || !tables.Type().IsMapType() || !tables.HasIndex(cty.StringVal(k)).True() {
					diags = diags.Append(attrError("tables_created_by", fmt.Sprintf("tables_created_by names %s, which table_grants doesn't list", k)))
				}
			}
		}
	}
	if r := cfg.GetAttr("on_remove"); known(r) && r.AsString() == onRemoveDelete && stringOr(cfg.GetAttr("name"), "") == postgresql.Superuser {
		diags = diags.Append(attrError("on_remove", "postgres is the superuser Conn3x runs psql as, so it can't be dropped"))
	}
	return diags
}

func planPgRole(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	// Role names are case-sensitive, so they're compared exactly.
	resp := planPassword(req, "postgresql_role", []string{"login", "attributes", "password_hmac", "database_grants", "schema_grants", "table_grants", "tables_created_by"}, planSynced)
	if resp.PlannedState.IsNull() || resp.Diagnostics.HasErrors() {
		return resp
	}
	vals := resp.PlannedState.AsValueMap()
	vals["tables_created_by"] = planCreators(req.Config.GetAttr("tables_created_by"), vals["table_grants"], req.PriorState)
	resp.PlannedState = cty.ObjectVal(vals)
	return resp
}

// planCreators is tables_created_by as planned: for each schema with table
// grants, the configured role, or the one apply resolved before, or
// unknown until apply reads the schema's owner.
func planCreators(cfg, tables, prior cty.Value) cty.Value {
	if !tables.IsWhollyKnown() || !cfg.IsWhollyKnown() {
		return cty.UnknownVal(cty.Map(cty.String))
	}
	if tables.IsNull() || tables.LengthInt() == 0 {
		return cty.NullVal(cty.Map(cty.String))
	}
	out := map[string]cty.Value{}
	for k := range tables.AsValueMap() {
		key := cty.StringVal(k)
		switch {
		case !cfg.IsNull() && cfg.HasIndex(key).True():
			out[k] = cfg.Index(key)
		case !prior.IsNull():
			if p := prior.GetAttr("tables_created_by"); p.IsWhollyKnown() && !p.IsNull() && p.HasIndex(key).True() {
				out[k] = p.Index(key)
				continue
			}
			out[k] = cty.UnknownVal(cty.String)
		default:
			out[k] = cty.UnknownVal(cty.String)
		}
	}
	return cty.MapVal(out)
}

func readPgRole(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	var extra []string
	resp := readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		r := pgRoleFrom(prior)
		s, err := postgresql.ReadRole(ctx, h, r.Name)
		if err != nil {
			return cty.NilVal, fmt.Errorf("postgresql_role %s: %w", r.Name, err)
		}
		ok := r.Matches(s)
		if g := pgGrantsFrom(prior); ok && s.Exists && (g.Databases != nil || g.Schemas != nil) {
			gs, err := postgresql.ReadGrants(ctx, h, r.Name, g.SchemaDatabases())
			if err != nil {
				return cty.NilVal, fmt.Errorf("postgresql_role %s: %w", r.Name, err)
			}
			g = g.WithCreators(gs)
			if extra, err = g.Extra(gs); err != nil {
				return cty.NilVal, fmt.Errorf("postgresql_role %s: %w", r.Name, err)
			}
			ok = g.Matches(gs)
		}
		return withSync(prior, ok), nil
	})
	if len(extra) > 0 && !resp.Diagnostics.HasErrors() {
		resp.Diagnostics = resp.Diagnostics.Append(tfdiags.SimpleWarning(fmt.Sprintf(
			"role %s has privileges the postgresql_role step doesn't list, which apply revokes: %s", req.PriorState.GetAttr("name").AsString(), strings.Join(extra, "; "))))
	}
	return resp
}

func applyPgRole(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if req.PlannedState.IsNull() {
		return applyPathResource(ctx, req, nil, func(ctx context.Context, h *hostConn, prior cty.Value) error {
			name := stringOr(prior.GetAttr("name"), "")
			if err := postgresql.DropRole(ctx, h, name); err != nil {
				return fmt.Errorf("postgresql_role %s: %w", name, err)
			}
			return nil
		})
	}
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("postgresql_role: %w", err))
		return resp
	}
	planned := req.PlannedState
	r := pgRoleFrom(planned)
	if err := r.Validate(); err != nil {
		return fail(err)
	}
	vals := planned.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	sum, password, err := passwordAtApply(req, "postgresql_role", r.Name)
	if err != nil {
		return fail(err)
	}
	vals["password_hmac"] = sum
	h, err := dialForApply(ctx, planned.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	s, err := postgresql.ReadRole(ctx, h, r.Name)
	if err != nil {
		return fail(err)
	}
	// A role dropped behind Conn3x's back is made again with its password.
	if wo := req.Config.GetAttr("password_wo"); password == nil && !wo.IsNull() && !s.Exists {
		p := wo.AsString()
		password = &p
	}
	if password != nil || !r.Matches(s) {
		if err := postgresql.ApplyRole(ctx, h, r, password); err != nil {
			return fail(fmt.Errorf("%s: %w", r.Name, err))
		}
	}
	if g := pgGrantsFrom(planned); g.Databases != nil || g.Schemas != nil {
		g, err := postgresql.ApplyGrants(ctx, h, r.Name, g)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", r.Name, err))
		}
		// Record whose new tables the defaults are for, as resolved.
		if t := planned.GetAttr("table_grants"); !t.IsNull() && t.LengthInt() > 0 {
			creators := map[string]cty.Value{}
			for k := range t.AsValueMap() {
				creators[k] = cty.StringVal(g.Schemas[k].CreatedBy)
			}
			vals["tables_created_by"] = cty.MapVal(creators)
		}
	}
	vals["in_sync"] = cty.True
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
