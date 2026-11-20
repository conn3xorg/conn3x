Use `mysql_variable` to set one system variable of the host's MySQL or MariaDB server, such as `max_connections`, without editing `my.cnf` or restarting. Conn3x runs `SET GLOBAL`, `SET PERSIST` or `SET PERSIST_ONLY` through the `mysql` client as root over the server's socket, the same way `mysql_database` and `mysql_user` do.

## Example usage

A value that lasts across restarts, on MySQL 8.0 or later:

```hcl
step "max_connections" {
  mysql_variable {
    name  = "max_connections"
    value = "500"
    mode  = "persist"
  }
}
```

A variable the server only reads at startup, written for the next one:

```hcl
step "log_buffer" {
  mysql_variable {
    name  = "innodb_log_buffer_size"
    value = "32M"
    mode  = "persist_only"
  }
}
```

The running value only, on MySQL or MariaDB:

```hcl
step "slow_queries" {
  mysql_variable {
    name  = "slow_query_log"
    value = "ON"
  }
}
```
<!-- reference -->
## How it works

**What the host needs.** MySQL or MariaDB has to be installed and running. Conn3x logs in as root over the server's socket, which needs root on the host, so set `become = true` in the circuit's `ssh` block unless you log in as root.

**Modes.**
- **`global`, the default,** changes the running value only. The next restart loses it, and the plan after the restart shows the change again.
- **`persist`** changes it and writes it to `mysqld-auto.cnf` in the data directory, so it lasts.
- **`persist_only`** writes `mysqld-auto.cnf` alone and leaves the running value. It's for variables the server only reads at startup, so it takes effect at the next restart, which this step never does.

Both persist modes need MySQL 8.0 or later. MariaDB has no `SET PERSIST`, so on MariaDB they fail before anything changes, and the message says to set the variable in a config file, such as circuit-mariadb's `settings`, instead.

**Reading.** On every plan, Conn3x reads the running value with `SHOW GLOBAL VARIABLES`, and for the persist modes what `mysqld-auto.cnf` holds, from `performance_schema.persisted_variables`. `in_sync` is true when the server has `value` where the mode puts it: running for `global`, in the file for `persist_only`, and both for `persist`. A name the server doesn't have fails the plan.

**Comparing.**
- A boolean compares in any spelling, so `1`, `on` and `true` are all `ON`.
- A number compares as a number, so `10` and `10.000000` are the same.
- A size suffix, `K`, `M`, `G` or `T`, is turned into bytes before anything else, since `SET` doesn't take one, unlike `my.cnf`. So `32M` is `33554432`.
- A set-valued variable, such as `sql_mode`, `log_output` or `tls_version`, compares as a set, since the server keeps its members in its own order. So `NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES` matches the server's `STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION`. Any other variable's value compares as a whole, commas and all, so a reordered `init_connect` is a change.
- `ANSI` and `TRADITIONAL` in `sql_mode` stand for the modes the server expands them into, so `TRADITIONAL` matches its full list. A mode added by hand beyond those is still a change. MariaDB's other combination modes (`DB2`, `MAXDB`, `MSSQL`, `ORACLE`, `POSTGRESQL`, `MYSQL323`, `MYSQL40`) expand differently between versions, so they're refused at validate. Give the modes they stand for instead.
- In a flag set, `optimizer_switch`, `optimizer_trace` or `optimizer_trace_features`, the `key=value` flags given only have to be among the server's, since it lists every flag and `SET` changes only the ones named.
- Other values compare without case.

**Applying.** Conn3x runs the mode's `SET`, then reads the variable back. A number or `ON`/`OFF` goes in bare, and anything else as a quoted string. MySQL rounds or caps some values, such as `innodb_buffer_pool_size` to a multiple of its chunk size. Then the step fails and names the value the server chose, so you can set that, rather than plan a change forever.

**Where it's written.** `mysqld-auto.cnf` is read after `my.cnf` and its `conf.d` files, so a persisted value wins over them. Don't set one variable both here and in a circuit's `settings`.

## Removal

When you delete a `mysql_variable` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the variable. `"delete"` puts it back:
- for `global` and `persist`, the running value goes back to its default with `SET GLOBAL ... = DEFAULT`;
- for the persist modes, `RESET PERSIST IF EXISTS` takes it out of `mysqld-auto.cnf`.

Changing `mode` from `persist` to `global` leaves what `mysqld-auto.cnf` holds.

## From Ansible

`conn3x convert ansible` turns `mysql_variables` tasks, from `community.mysql` or `ansible.mysql`, into `mysql_variable` steps, with `variable` as `name`, and `value` and `mode` carried across. A value with a size suffix converts, with a note: Ansible sends it to `SET` as a string, which MySQL refuses for a number, where this step turns it into bytes. A task without `value`, which only reads the variable, stays a TODO, and so does one with connection settings such as `login_host` or `login_port`, since Conn3x connects as root over the socket.
