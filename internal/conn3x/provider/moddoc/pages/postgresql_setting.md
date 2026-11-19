Use `postgresql_setting` to set one server setting of the host's PostgreSQL server, such as `work_mem`, `max_connections`, or `shared_preload_libraries` for `pg_stat_statements`. Conn3x runs `ALTER SYSTEM SET` through `psql` on the host as the `postgres` user, the same way `postgresql_database` and `postgresql_role` do, and then has the server reload. It never restarts the server.

## Example usage

A setting the server takes on a reload:

```hcl
step "work_mem" {
  postgresql_setting {
    name  = "work_mem"
    value = "64MB"
  }
}
```

A setting that waits for a restart, with a [handler](/concepts#handlers) in the same circuit that does the restart:

```hcl
step "shared_buffers" {
  postgresql_setting {
    name  = "shared_buffers"
    value = "1GB"
  }
  notify = [handler.restart_postgresql]
}
```

```hcl
handler "restart_postgresql" {
  service {
    name = "postgresql"
  }
}
```

A list:

```hcl
step "preload" {
  postgresql_setting {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements, auto_explain"
  }
  notify = [handler.restart_postgresql]
}
```
<!-- reference -->
## How it works

**What the host needs.** PostgreSQL has to be installed and running. Conn3x runs `psql` with `runuser -u postgres`, which needs root, so set `become = true` in the circuit's `ssh` block unless you log in as root.

**Reading.** On every plan, Conn3x reads the setting from `pg_settings`. `in_sync` is true when the server has `value`. While the setting waits for a restart (`pending_restart`), the value that counts is the last one the configuration files give it, from `pg_file_settings`, so a setting you've set but not restarted for doesn't plan a change every run. `restart_required` is true while it waits.

**Comparing.** A number is compared in the setting's own unit, as PostgreSQL reads it:
- `256MB`, `262144kB` and `0.25GB` are the same `shared_buffers`, and so are `60s` and `1min` for a timeout.
- A number without a unit is in the setting's unit, as `pg_settings.unit` shows it.
- Units are case-sensitive, and `kB` is 1024 bytes.
- An integer setting is rounded as PostgreSQL rounds it: a fraction goes to the nearest whole smaller unit first, then to the nearest whole setting unit, with a half to even. So `100kB` on a setting counted in 8 kB pages is 12 pages, and plans clean once set.

`on`, `true`, `yes` and `1` are the same bool, and so are their opposites. An enum is compared without case. Any other string is compared as written.

**Lists.** `search_path`, `shared_preload_libraries`, `session_preload_libraries`, `local_preload_libraries`, `temp_tablespaces` and `unix_socket_directories` take a comma-separated list. Conn3x passes each item to `ALTER SYSTEM` on its own, since PostgreSQL would read one quoted `'a, b'` as a single name with a comma in it, and compares the items in order.

**Applying.** Conn3x runs `ALTER SYSTEM SET` and `SELECT pg_reload_conf()`, then reads the setting back and fails if the server doesn't have `value`. A setting such as `shared_buffers` or `shared_preload_libraries` only takes effect after a restart: the step sets it, `restart_required` becomes true, and a handler restarts the server when you `notify` one.

**Where it's written.** `ALTER SYSTEM` writes `postgresql.auto.conf`, which PostgreSQL reads after `postgresql.conf` and its `conf.d` files, so it wins over them. Don't set one name both here and in circuit-postgres's `settings`, which writes `conf.d/conn3x.conf`: this step's value would win, and the circuit would plan a change it can't make.

## Removal

When you delete a `postgresql_setting` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the setting in `postgresql.auto.conf`. `"delete"` runs `ALTER SYSTEM RESET`, so `postgresql.conf` and the server's default decide it again, and reloads. A setting that waits for a restart keeps its old value until the next one.

## From Ansible

`conn3x convert ansible` turns `community.postgresql.postgresql_alter_system` tasks into `postgresql_setting` steps, and the older `postgresql_set` tasks too. `param` (or `name`) and `value` carry over. `login_db` is dropped, since settings are server-wide. These stay a TODO with the reason: `value: _RESET` and `reset: true`, since this step resets only when it's removed with `on_remove = "delete"`, and connection settings such as `login_host`, `login_user`, `port` or `session_role`, since Conn3x connects as `postgres` on the host.
