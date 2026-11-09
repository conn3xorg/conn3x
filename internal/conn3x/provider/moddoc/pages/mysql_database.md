Use `mysql_database` to make an application's database in the MySQL or MariaDB server on a host. Conn3x runs the `mysql` client on the host as root, so nothing on your machine needs a database driver or a route to port 3306.

## Example usage

A database with the character set most apps want:

```hcl
step "app_db" {
  mysql_database {
    name      = "app"
    charset   = "utf8mb4"
    collation = "utf8mb4_unicode_ci"
  }
}
```

Drop it when the step is removed:

```hcl
step "scratch_db" {
  mysql_database {
    name      = "scratch"
    on_remove = "delete"
  }
}
```
<!-- reference -->
## How it works

**What the host needs.** MySQL or MariaDB has to be installed and running. Conn3x logs in as root over the server's socket, which is how both servers set up root at install, so set `become = true` in the circuit's `ssh` block unless you log in as root. Every statement goes to the client on stdin, never on a command line.

**Character set and collation.** Leave them unset and a new database gets the server's defaults, and an existing one keeps its own. Changing either one runs `ALTER DATABASE`, which changes the default for tables made afterwards. Tables already there keep theirs.

**Changes.** Changing `name` makes a new database, and `on_remove` decides what happens to the old one.

## Removal

When you delete a `mysql_database` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the database. `"delete"` drops it and every table in it. Conn3x never drops `mysql`, `information_schema`, `performance_schema` or `sys`.
