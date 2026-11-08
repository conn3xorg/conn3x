Use `firewalld` to allow a service or a port through firewalld, the firewall on Rocky Linux, RHEL, AlmaLinux and Fedora. Each step opens one service or one port in one zone. On Debian and Ubuntu, use [`ufw`](/modules/ufw) instead.

## Example usage

Allow a firewalld service in the default zone:

```hcl
step "https" {
  firewalld {
    service = "https"
  }
}
```

Open a port in a named zone:

```hcl
step "app_port" {
  firewalld {
    zone = "internal"
    port = "8080/tcp"
  }
}
```

Open several ports, one instance per port and host:

```hcl
step "ports" {
  for_each = ["8080/tcp", "60000-61000/udp"]
  firewalld {
    port = item.value
  }
}
```

Guard the rule that lets SSH in, so removing it later can't lock Conn3x out for good:

```hcl
step "ssh" {
  firewalld {
    service       = "ssh"
    confirm_after = "60s"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks `firewall-cmd` whether the zone allows the service or port, once for the running firewall and once with `--permanent`. `in_sync` is true only when both allow it. firewalld must be running: if it isn't, the step fails and asks you to install and start it in an earlier step.

**Applying.** Conn3x runs `firewall-cmd --add-service` or `--add-port`, then the same with `--permanent`, so the rule takes effect now and survives a reload or a reboot. Without `zone`, both go to firewalld's default zone.

**Confirming.** Removing the rule that lets SSH in can lock Conn3x out. With `confirm_after`, the host schedules the commands that take the change back with `systemd-run`, due that long after, before Conn3x makes it. The undo is a timer in the host's own systemd, so it runs even if Conn3x goes away mid-apply. Conn3x then logs in again over a new connection with the circuit's whole `ssh` block, jump hosts and host key check included, and cancels the undo once that works. If the change fails, Conn3x takes it back at once. If the new login doesn't come in time, the host takes the change back by itself, and Conn3x fails the step saying whether the host answers again. The guard covers removing the step too, using the `confirm_after` the step had, and it only takes back what changed. `confirm_after` is between `10s` and `1h` and needs systemd on the host.

**Rules.** Set exactly one of `service` and `port`. A port takes a protocol, `tcp`, `udp`, `sctp` or `dccp`, and may be a range such as `60000-61000/udp`.

**Changes.** `zone`, `service` and `port` identify the rule, so changing any of them replaces the step. With the default `on_remove`, the old rule is removed from the firewall.

## Removal

When you delete a `firewalld` step, `on_remove` decides what happens on the host. The default is `"delete"`, unlike most modules: Conn3x removes the rule from the running and the permanent firewall, so a port you stop managing doesn't stay open. `"forget"` leaves it open.

## From Ansible

`conn3x convert ansible` turns `ansible.posix.firewalld` tasks that set `service` or `port` into `firewalld` steps. A task must set both `permanent: true` and `immediate: true`, since Conn3x always changes both; one that doesn't stays a TODO, as does a task with a `state` other than `enabled` or with any other argument, such as `rich_rule`, `source` or `interface`.
