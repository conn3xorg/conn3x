Use `mysql_user` to give an application its own account in the MySQL or MariaDB server on a host, with exactly the database privileges it needs. Conn3x runs the `mysql` client on the host as root, so nothing on your machine needs a database driver or a route to port 3306.

## Example usage

An account for the app on the same host, with full use of its own database:

```hcl
step "app_user" {
  mysql_user {
    name        = "app"
    password_wo = "use an ephemeral variable here"
    grants = {
      app = ["ALL PRIVILEGES"]
    }
  }
}
```

A read-only account that connects from the app servers' network:

```hcl
step "reports_user" {
  mysql_user {
    name        = "reports"
    host        = "10.0.1.%"
    password_wo = "use an ephemeral variable here"
    grants = {
      app = ["SELECT"]
    }
  }
}
```
<!-- reference -->
## How it works

**What the host needs.** MySQL or MariaDB has to be installed and running. Conn3x logs in as root over the server's socket, which is how both servers set up root at install, so set `become = true` in the circuit's `ssh` block unless you log in as root. Every statement goes to the client on stdin, never on a command line.

**The account.** `name` and `host` together are the account, as in `'app'@'localhost'`. `host` defaults to `localhost`. Changing either one makes a new account, and `on_remove` decides what happens to the old one. Conn3x never manages `root` or the server's own accounts, such as `mysql.sys` or `mariadb.sys`.

**Grants.** `grants` is the whole list of the account's database-level privileges, by database, as `SHOW GRANTS` prints them: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`, `ALTER`, `INDEX` and the rest, or `ALL PRIVILEGES` on its own. A database that isn't listed loses its grant. Leave `grants` unset and Conn3x leaves the account's privileges alone. Global and table-level grants are never touched. MySQL reads `_` and `%` in a granted database name as wildcards, so a grant on `app_db` also covers `appXdb`.

**Passwords.** A new account needs `password_wo`: without one, the server would let anyone log in as it with an empty password. The password reaches the server on the client's stdin, inside the `CREATE USER` or `ALTER USER` statement, so the server sees it as typed, and anything that records the statements it receives, such as a general query log turned on by hand, can hold it. If the server rejects the statement, Conn3x cuts the server's quote of it from the error. State keeps only a keyed hash, `password_hmac`. The password is set when the account is made and again whenever the value you give changes. A password changed on the server doesn't show as drift.

## Removal

When you delete a `mysql_user` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the account. `"delete"` drops it, and its grants with it.
