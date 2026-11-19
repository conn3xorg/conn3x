Use `postgresql_extension` to make sure a database on the host's PostgreSQL server has an extension, such as `pgcrypto`, `pg_stat_statements` or `postgis`. Conn3x runs `psql` on the host as the `postgres` user, the same way `postgresql_database` and `postgresql_role` do.

## Example usage

`pgcrypto` in the app's database. On Debian and Ubuntu it comes with the server. On Rocky Linux and Fedora it's in `postgresql-contrib`, so add a `package` step for that first:

```hcl
step "app_crypto" {
  postgresql_extension {
    name     = "pgcrypto"
    database = "app"
  }
}
```

An extension that comes in its own package needs that package first:

```hcl
step "postgis_package" {
  package {
    name = "postgresql-17-postgis-3"
  }
}
```

```hcl
step "gis_postgis" {
  postgresql_extension {
    name     = "postgis"
    database = "gis"
    schema   = "public"
    cascade  = true
  }
}
```
<!-- reference -->
## How it works

**What the host needs.** PostgreSQL has to be installed and running, and the database has to exist, so make it in an earlier `postgresql_database` step. Conn3x runs `psql` with `runuser -u postgres`, which needs root, so set `become = true` in the circuit's `ssh` block unless you log in as root. If the extension's files aren't on the host, PostgreSQL refuses, and the error says to install its package in an earlier `package` step.

**Reading.** On every plan, Conn3x reads the extension's schema and version from `pg_extension` in that database. `in_sync` is true when the extension is there with what you set. Anything you leave unset isn't compared.

**Creating.** A missing extension is made with `CREATE EXTENSION IF NOT EXISTS`, with `SCHEMA`, `VERSION` and `CASCADE` when you set them. `cascade = true` also creates the extensions it needs.

**Changes.** A different `version` runs `ALTER EXTENSION ... UPDATE TO` that version, and a different `schema` runs `ALTER EXTENSION ... SET SCHEMA`. PostgreSQL refuses either one when the extension doesn't support it, and the apply fails with its message. Changing `name` or `database` makes a new extension, and `on_remove` decides what happens to the old one.

## Removal

When you delete a `postgresql_extension` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the extension. `"delete"` drops it, without `CASCADE`, so PostgreSQL refuses while a table or another extension depends on it.

## From Ansible

`conn3x convert ansible` turns `community.postgresql.postgresql_ext` tasks into `postgresql_extension` steps. `name` (or `ext`) and `db` (or `login_db`) carry over, along with `schema`, `version` and `cascade`. These stay a TODO with the reason: `state: absent`, `version: latest`, `comment`, and connection settings such as `login_host`, `login_user` or `port`, since Conn3x connects as `postgres` on the host.
