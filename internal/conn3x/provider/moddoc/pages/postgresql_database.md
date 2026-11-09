Use `postgresql_database` to make sure the PostgreSQL server on a host has a database, and who owns it. Conn3x runs `psql` on the host as the `postgres` user, so nothing on your machine needs a database driver or a route to port 5432.

## Example usage

A database for the app, owned by its role. The role has to exist first:

```hcl
step "app_role" {
  postgresql_role {
    name        = "app"
    password_wo = "use an ephemeral variable here"
  }
}
```

```hcl
step "app_db" {
  postgresql_database {
    name     = "app"
    owner    = "app"
    encoding = "UTF8"
  }
}
```
<!-- reference -->
## How it works

**What the host needs.** PostgreSQL has to be installed and running, and `psql` has to be on the host. Conn3x runs it with `runuser -u postgres`, which needs root, so set `become = true` in the circuit's `ssh` block unless you log in as root. Every statement goes to `psql` on stdin, never on a command line.

**Reading.** On every plan, Conn3x reads the database's owner and encoding from `pg_database`. `in_sync` is true when the database exists and has what you set. Anything you leave unset isn't compared.

**Encoding.** A new database with `encoding` is made from `template0`, which takes any encoding. PostgreSQL can't change a database's encoding afterwards, so a database that already has another one fails the apply, saying so, instead of planning a change on every run. Dump it, make it again with the new encoding, and restore.

**Changes.** Changing `owner` hands the database to that role. Changing `name` doesn't rename anything: Conn3x makes a new, empty database, and `on_remove` decides what happens to the old one.

## Removal

When you delete a `postgresql_database` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the database. `"delete"` drops it and everything in it, which can't be undone. PostgreSQL refuses while anyone is connected to it. Conn3x never drops `postgres`, `template0` or `template1`.
