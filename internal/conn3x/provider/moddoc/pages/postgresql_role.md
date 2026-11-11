Use `postgresql_role` to give an application its own login in the PostgreSQL server on a host, or to make a group role others join. Conn3x runs `psql` on the host as the `postgres` user, so nothing on your machine needs a database driver or a route to port 5432.

## Example usage

A login for the app, allowed to create databases:

```hcl
step "app_role" {
  postgresql_role {
    name        = "app"
    attributes  = ["CREATEDB"]
    password_wo = "use an ephemeral variable here"
  }
}
```

A group role that can't log in:

```hcl
step "readers" {
  postgresql_role {
    name  = "readers"
    login = false
  }
}
```

An app's login that can reach its database, use one schema, and read and write the rows of every table in it, including tables made later:

```hcl
step "app_role" {
  postgresql_role {
    name            = "app"
    password_wo     = "use an ephemeral variable here"
    database_grants = { shop = ["CONNECT"] }
    schema_grants   = { "shop.sales" = ["USAGE"] }
    table_grants    = { "shop.sales" = ["SELECT", "INSERT", "UPDATE", "DELETE"] }
  }
}
```

Take every attribute away from an existing role:

```hcl
step "report_user" {
  postgresql_role {
    name       = "reports"
    attributes = []
  }
}
```
<!-- reference -->
## How it works

**What the host needs.** PostgreSQL has to be installed and running, and `psql` has to be on the host. Conn3x runs it with `runuser -u postgres`, which needs root, so set `become = true` in the circuit's `ssh` block unless you log in as root. Every statement goes to `psql` on stdin, never on a command line.

**Attributes.** `attributes` is the whole list: anything from `SUPERUSER`, `CREATEDB`, `CREATEROLE`, `REPLICATION` and `BYPASSRLS` that isn't listed is taken away. Leave it unset and Conn3x leaves the role's attributes alone; a new role then gets none of them. `login` defaults to `true`.

**Passwords.** Conn3x turns `password_wo` into a SCRAM-SHA-256 verifier on your machine, with a random salt and PostgreSQL's 4096 iterations, and sends only that. The plain text never reaches the host, so it can't turn up in the server's logs, in `pg_stat_activity` or in shell history. State keeps a keyed hash, `password_hmac`. The password is set when the role is made and again whenever the value you give changes. A password changed on the server doesn't show as drift. Passwords are printable ASCII only: the server normalizes other characters before checking them, and Conn3x doesn't, so a login could fail.

**Grants.** Three maps give the role its privileges, and each is the whole list: a privilege the role has that the map doesn't list is revoked, and the plan's warning names it. Leave all three unset and Conn3x leaves the role's privileges alone.

- **`database_grants`:** database privileges by database, from `CONNECT`, `CREATE` and `TEMPORARY`. A database that isn't listed loses the role's privileges on it.
- **`schema_grants`:** schema privileges, from `USAGE` and `CREATE`, keyed `database.schema`, such as `"shop.sales"`.
- **`table_grants`:** privileges on every table in a schema, keyed the same way, from `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES` and `TRIGGER`.
  - **Tables made later:** default privileges give the same to tables made later by `tables_created_by`. Unset, that's the schema's owner when the step first grants there, and the plan shows it, so you can see whose new tables are covered. Set it when someone else makes the tables, such as `tables_created_by = { "shop.sales" = "migrator" }`.
  - **Per schema:** a schema is in sync when every table in it has exactly the listed privileges.

Conn3x reads them with `psql` in each database `schema_grants` or `table_grants` names, and runs the revokes and grants for each database in one transaction.

What they don't reach, which a security review will want to know:

- **`PUBLIC`.** Grants to `PUBLIC` aren't read or revoked. Out of the box every role can `CONNECT` to every database and make `TEMPORARY` tables there through `PUBLIC`, and can use each database's `public` schema. So `database_grants = { shop = ["CONNECT"] }` doesn't by itself keep the role out of other databases. Run `REVOKE CONNECT, TEMPORARY ON DATABASE <name> FROM PUBLIC` on the databases that need it.
- **Databases the maps don't name.** Schema and table privileges in a database that neither `schema_grants` nor `table_grants` names are neither read nor revoked. Database privileges are read on every database.
- **What the role owns.** An owner has every privilege on what it owns, whatever is granted, so a database or schema the role owns can't be listed, and the step says so. Tables it owns are left out of the check.
- **Grants made by others.** As the `postgres` superuser, a revoke acts for the object's owner. A privilege another role granted with grant option can only be revoked by that role, and the apply fails naming it.
- **Single tables, sequences and functions** aren't managed.

**The superuser.** The `postgres` role is the one Conn3x runs as. A step can't take its `LOGIN` or `SUPERUSER` away, and can't drop it.

**Changes.** Changing `login`, `attributes`, the grants or the password updates the role in place. Changing `name` makes a new role, and `on_remove` decides what happens to the old one.

## Removal

When you delete a `postgresql_role` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the role. `"delete"` drops it. PostgreSQL refuses to drop a role that still owns a database or other objects, and the apply fails with its message; give those to another role first.

## From Ansible

`conn3x convert ansible` turns `postgresql_user` tasks into `postgresql_role` steps. A `priv` of database privileges with `db`, such as `CONNECT/TEMP`, becomes `database_grants`, with a note that it is now the whole list, where Ansible only added. A `priv` on single tables, `postgresql_privs` tasks and `grant_option` stay for review: a role's grants live on its own step.
