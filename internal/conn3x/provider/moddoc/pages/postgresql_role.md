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

**The superuser.** The `postgres` role is the one Conn3x runs as. A step can't take its `LOGIN` or `SUPERUSER` away, and can't drop it.

**Changes.** Changing `login`, `attributes` or the password updates the role in place. Changing `name` makes a new role, and `on_remove` decides what happens to the old one.

## Removal

When you delete a `postgresql_role` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the role. `"delete"` drops it. PostgreSQL refuses to drop a role that still owns a database or other objects, and the apply fails with its message; give those to another role first.
