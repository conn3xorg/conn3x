Use `postgresql_schema` to make sure a database on the host's PostgreSQL server has a schema, such as one that keeps an application's tables out of `public`, or one a reporting tool gets to itself. Conn3x runs `psql` on the host as the `postgres` user, the same way `postgresql_database` and `postgresql_role` do.

## Example usage

A `reporting` schema in the app's database, owned by the app's role, and a reporting role that can use it:

```hcl
step "app_db" {
  postgresql_database {
    name = "app"
  }
}
```

```hcl
step "app_role" {
  postgresql_role {
    name = "app"
  }
}
```

```hcl
step "reporting_schema" {
  postgresql_schema {
    name     = "reporting"
    database = "app"
    owner    = "app"
  }
}
```

```hcl
step "reporter" {
  postgresql_role {
    name          = "reporter"
    schema_grants = { "app.reporting" = ["USAGE"] }
  }
}
```
<!-- reference -->
## How it works

**What the host needs.** PostgreSQL has to be installed and running, and the database has to exist, so make it in an earlier `postgresql_database` step. An `owner` has to exist too, so make it in an earlier `postgresql_role` step. Conn3x runs `psql` with `runuser -u postgres`, which needs root, so set `become = true` in the circuit's `ssh` block unless you log in as root.

**Reading.** On every plan, Conn3x reads the schema and its owner from `pg_namespace` in that database. `in_sync` is true when the schema is there, owned by `owner` if you set one. An unset `owner` isn't compared.

**Creating.** A missing schema is made with `CREATE SCHEMA IF NOT EXISTS`, with `AUTHORIZATION` when `owner` is set. Without `owner`, PostgreSQL makes `postgres` the owner. Names starting with `pg_` are PostgreSQL's own, and a step with one fails at validate.

**Changes.** A different `owner` runs `ALTER SCHEMA ... OWNER TO`. Changing `name` or `database` makes a new schema, and `on_remove` decides what happens to the old one.

## Removal

When you delete a `postgresql_schema` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the schema. `"delete"` drops it, without `CASCADE`, so PostgreSQL refuses while it still holds a table or anything else.

## From Ansible

`conn3x convert ansible` turns `community.postgresql.postgresql_schema` tasks into `postgresql_schema` steps. `name` (or `schema`) and `owner` carry over, and `db` (or `login_db` or `database`) becomes `database`. A task without one gets `database = "postgres"`, since that's where Ansible makes the schema then. These stay a TODO with the reason: `state: absent`, `cascade_drop: true`, `comment`, and connection settings such as `login_host`, `login_user` or `port`, since Conn3x connects as `postgres` on the host.
