// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/configs/configschema"
	"github.com/opentofu/opentofu/internal/conn3x/modules/mysql"
	"github.com/opentofu/opentofu/internal/providers"
	"github.com/opentofu/opentofu/internal/tfdiags"
)

func mysqlDatabaseSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "A database in the MySQL or MariaDB server on the host, managed through the mysql client as root over the server's socket. Settings left unset are left as they are.",
		Attributes: map[string]*configschema.Attribute{
			"id":        {Type: cty.String, Computed: true},
			"revision":  revisionAttr(),
			"name":      {Type: cty.String, Required: true, Description: "Database name, up to 64 characters. Renaming makes a new database; the old one stays unless on_remove is \"delete\"."},
			"charset":   {Type: cty.String, Optional: true, Description: "Default character set, such as utf8mb4. Changing it changes the default for new tables only."},
			"collation": {Type: cty.String, Optional: true, Description: "Default collation, such as utf8mb4_unicode_ci. Changing it changes the default for new tables only."},
			"on_remove": {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the database, \"delete\" drops it and everything in it."},
			"in_sync":   {Type: cty.Bool, Computed: true, Description: "Whether the database matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func mysqlDatabaseFrom(v cty.Value) mysql.Database {
	return mysql.Database{Name: stringOr(v.GetAttr("name"), ""), Charset: stringOr(v.GetAttr("charset"), ""), Collation: stringOr(v.GetAttr("collation"), "")}
}

func validateMysqlDatabase(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() || !cfg.IsWhollyKnown() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if err := mysqlDatabaseFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planMysqlDatabase(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	return planSynced(req, "mysql_database", []string{"name"}, []string{"charset", "collation"})
}

func readMysqlDatabase(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		d := mysqlDatabaseFrom(prior)
		s, err := mysql.ReadDatabase(ctx, h, d.Name)
		if err != nil {
			return cty.NilVal, fmt.Errorf("mysql_database %s: %w", d.Name, err)
		}
		return withSync(prior, d.Matches(s)), nil
	})
}

func applyMysqlDatabase(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	return applyPathResource(ctx, req,
		func(ctx context.Context, h *hostConn, planned cty.Value) (cty.Value, error) {
			d := mysqlDatabaseFrom(planned)
			if err := mysql.ApplyDatabase(ctx, h, d); err != nil {
				return cty.NilVal, fmt.Errorf("mysql_database %s: %w", d.Name, err)
			}
			return withSync(planned, true), nil
		},
		func(ctx context.Context, h *hostConn, prior cty.Value) error {
			name := stringOr(prior.GetAttr("name"), "")
			if err := mysql.DropDatabase(ctx, h, name); err != nil {
				return fmt.Errorf("mysql_database %s: %w", name, err)
			}
			return nil
		})
}

func mysqlUserSchema() providers.Schema {
	return providers.Schema{Block: &configschema.Block{
		Description: "An account in the MySQL or MariaDB server on the host, such as an application's login, and its database grants, managed through the mysql client as root over the server's socket.",
		Attributes: map[string]*configschema.Attribute{
			"id":       {Type: cty.String, Computed: true},
			"revision": revisionAttr(),
			"name":     {Type: cty.String, Required: true, Description: "User name, up to 32 characters. Never root or one of the server's own accounts."},
			"host":     {Type: cty.String, Optional: true, Computed: true, Description: "Where the user may connect from, such as localhost (the default), 10.0.0.% or %. name and host together are the account."},
			"grants":   {Type: cty.Map(cty.Set(cty.String)), Optional: true, Description: "Exactly the user's database-level privileges, by database, such as { app = [\"SELECT\", \"INSERT\"] } or { app = [\"ALL PRIVILEGES\"] }. A database not listed loses its grant. Unset leaves grants as they are; global and table grants are never changed."},
			"password_wo": {
				Type: cty.String, Optional: true, WriteOnly: true, Sensitive: true,
				Description: "Password, kept out of plan and state: state records only password_hmac. It reaches the server on the mysql client's stdin, inside the statement, so the server sees it as typed. Required for a new user. It's set when the user is made and whenever this value changes. A password changed on the server isn't detected.",
			},
			"password_hmac": {Type: cty.String, Computed: true, Description: "HMAC-SHA256 of password_wo, keyed by CONN3X_HMAC_KEY or ~/.config/conn3x/hmac.key. Null without password_wo."},
			"on_remove":     {Type: cty.String, Optional: true, Computed: true, Description: "What happens on the host when this resource is removed: \"forget\" (default) leaves the user, \"delete\" drops it."},
			"in_sync":       {Type: cty.Bool, Computed: true, Description: "Whether the user matched at the last refresh."},
		},
		BlockTypes: map[string]*configschema.NestedBlock{"ssh": connectionBlock()},
	}}
}

func mysqlUserFrom(v cty.Value) mysql.User {
	u := mysql.User{Name: stringOr(v.GetAttr("name"), ""), Host: stringOr(v.GetAttr("host"), "localhost")}
	if g := v.GetAttr("grants"); known(g) {
		u.Grants = map[string][]string{}
		for db, privs := range g.AsValueMap() {
			u.Grants[db] = []string{}
			for _, p := range privs.AsValueSlice() {
				u.Grants[db] = append(u.Grants[db], p.AsString())
			}
		}
	}
	return u
}

func validateMysqlUser(cfg cty.Value) tfdiags.Diagnostics {
	var diags tfdiags.Diagnostics
	if cfg.IsNull() {
		return diags
	}
	diags = diags.Append(validateOnRemove(cfg))
	if pw := cfg.GetAttr("password_wo"); known(pw) {
		if err := mysql.ValidPassword(pw.AsString()); err != nil {
			diags = diags.Append(attrError("password_wo", err.Error()))
		}
	}
	for _, a := range []string{"name", "host", "grants"} {
		if !cfg.GetAttr(a).IsWhollyKnown() {
			return diags
		}
	}
	if err := mysqlUserFrom(cfg).Validate(); err != nil {
		diags = diags.Append(attrError("name", err.Error()))
	}
	return diags
}

func planMysqlUser(req providers.PlanResourceChangeRequest) providers.PlanResourceChangeResponse {
	if !req.ProposedNewState.IsNull() && req.ProposedNewState.GetAttr("host").IsNull() {
		vals := req.ProposedNewState.AsValueMap()
		vals["host"] = cty.StringVal("localhost")
		req.ProposedNewState = cty.ObjectVal(vals)
	}
	// name and host are the account, and both compare exactly.
	return planPassword(req, "mysql_user", []string{"grants", "password_hmac"},
		func(req providers.PlanResourceChangeRequest, kind string, _, settings []string) providers.PlanResourceChangeResponse {
			return planSynced(req, kind, []string{"name", "host"}, settings)
		})
}

func readMysqlUser(ctx context.Context, req providers.ReadResourceRequest) providers.ReadResourceResponse {
	return readPathResource(ctx, req, func(ctx context.Context, h *hostConn, prior cty.Value) (cty.Value, error) {
		u := mysqlUserFrom(prior)
		s, err := mysql.ReadUser(ctx, h, u)
		if err != nil {
			return cty.NilVal, fmt.Errorf("mysql_user %s@%s: %w", u.Name, u.Host, err)
		}
		return withSync(prior, u.Matches(s)), nil
	})
}

func applyMysqlUser(ctx context.Context, req providers.ApplyResourceChangeRequest) providers.ApplyResourceChangeResponse {
	if req.PlannedState.IsNull() {
		return applyPathResource(ctx, req, nil, func(ctx context.Context, h *hostConn, prior cty.Value) error {
			u := mysqlUserFrom(prior)
			if err := mysql.DropUser(ctx, h, u); err != nil {
				return fmt.Errorf("mysql_user %s@%s: %w", u.Name, u.Host, err)
			}
			return nil
		})
	}
	var resp providers.ApplyResourceChangeResponse
	fail := func(err error) providers.ApplyResourceChangeResponse {
		resp.Diagnostics = resp.Diagnostics.Append(fmt.Errorf("mysql_user: %w", err))
		return resp
	}
	planned := req.PlannedState
	u := mysqlUserFrom(planned)
	if err := u.Validate(); err != nil {
		return fail(err)
	}
	vals := planned.AsValueMap()
	vals["password_wo"] = cty.NullVal(cty.String)
	sum, password, err := passwordAtApply(req, "mysql_user", u.Name)
	if err != nil {
		return fail(err)
	}
	vals["password_hmac"] = sum
	h, err := dialForApply(ctx, planned.GetAttr("ssh"))
	if err != nil {
		resp.Diagnostics = resp.Diagnostics.Append(attrError("ssh", err.Error()))
		return resp
	}
	s, err := mysql.ReadUser(ctx, h, u)
	if err != nil {
		return fail(err)
	}
	// A user dropped behind Conn3x's back is made again with its password.
	if wo := req.Config.GetAttr("password_wo"); password == nil && !wo.IsNull() && !s.Exists {
		p := wo.AsString()
		password = &p
	}
	if password != nil || !u.Matches(s) {
		if err := mysql.ApplyUser(ctx, h, u, password); err != nil {
			return fail(fmt.Errorf("%s@%s: %w", u.Name, u.Host, err))
		}
	}
	vals["in_sync"] = cty.True
	resp.NewState = cty.ObjectVal(vals)
	return resp
}
