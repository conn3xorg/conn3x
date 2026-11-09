// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"slices"

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
			"password_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of password_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null without password_wo."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the role, \"delete\" drops it, which PostgreSQL refuses while it owns anything."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the role matched at the last refresh."},
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
	if r := cfg.GetAttr("on_remove"); known(r) && r.AsString() == onRemoveDelete && stringOr(cfg.GetAttr("name"), "") == postgresql.Superuser {
		diags = diags.Append(attrError("on_remove", "postgres is the superuser Conn3x runs psql as, so it can't be dropped"))
	}
	return diags
}

func planPgRole(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	// Role names are case-sensitive, so they're compared exactly.
	return planPassword(req, "postgresql_role", []string{"login", "attributes", "password_hmac"}, planSynced)
}

func readPgRole(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		r := pgRoleFrom(prior)
		s, err := postgresql.ReadRole(ctx, h, r.Name)
		if err != nil {
			return cty.NilVal, fmt.Errorf("postgresql_role %s: %w", r.Name, err)
		}
		return withSync(prior, r.Matches(s)), nil
	})
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
	vals["in_sync"] = cty.True
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
