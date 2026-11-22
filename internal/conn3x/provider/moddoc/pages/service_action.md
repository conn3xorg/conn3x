Use `service_action` to restart or reload a systemd unit at a set point in a circuit, whenever something it reads changes. A [handler](/concepts#handlers) does the same after all of a circuit's steps; a `service_action` step does it where it's written, so the steps after it find the unit running with the new settings.

## Example usage

Restart MySQL when its configuration changes, before the steps after it log in:

```hcl
step "config" {
  file {
    path    = "/etc/mysql/conf.d/conn3x.cnf"
    content = "[mysqld]\nbind-address = 127.0.0.1\n"
  }
}

step "restart" {
  service_action {
    name     = "mysql"
    triggers = { config = conn3x_file.docs__config[each.key].revision }
  }
}
```

The address is the step's resource address, `conn3x_file.CIRCUIT__STEP`, here in a circuit named `docs`.

Reload rather than restart:

```hcl
step "site" {
  file {
    path    = "/etc/nginx/conf.d/site.conf"
    content = "server { listen 8080; }\n"
  }
}

step "reload_nginx" {
  service_action {
    name     = "nginx"
    action   = "reload"
    triggers = { site = conn3x_file.docs__site[each.key].revision }
  }
}
```
<!-- reference -->
## How it works

**When it runs.** The step runs its action when it's created, and again whenever `triggers` changes, which replaces it. A plan that changes nothing else leaves it alone. Refresh never finds drift: an action leaves nothing on the host to compare.

**Applying.** `action = "restart"`, the default, runs `systemctl restart`. `"reload"` runs `systemctl reload`, and starts the unit instead when it isn't running, since a reload asks for the new configuration to be in use. If the unit file changed since systemd last loaded it, Conn3x runs `systemctl daemon-reload` first. `serial = true` acts on one host at a time.

**When systemd re-executes.** An upgrade of libc6 or systemd makes systemd re-execute itself, and while it does, `systemctl` can't reach it for a moment. A `service_action` step tries again for up to 30 seconds when that happens. A `command` step that runs `systemctl restart` fails instead, which is why [`conn3x lint`](/reference/cli/lint) warns about one (C3X103).

**Names.** A `name` without a dot gets `.service` added, so `"mysql"` means `mysql.service`.

## Removal

When you delete a `service_action` step, Conn3x stops tracking it. Nothing runs on the host.

## From a command step

A step such as

```hcl
step "config" {
  file {
    path    = "/etc/mysql/conf.d/conn3x.cnf"
    content = "[mysqld]\n"
  }
}

step "restart" {
  command {
    command  = "systemctl daemon-reload && systemctl restart mysql"
    triggers = { config = conn3x_file.docs__config[each.key].revision }
  }
}
```

becomes a `service_action` step with the same `triggers`. The `daemon-reload` isn't needed: Conn3x runs it when the unit file changed.
