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
Open a port to one network only, with a rich rule:

```hcl
step "postgres" {
  firewalld {
    zone      = "public"
    rich_rule = "rule family=ipv4 source address=10.0.0.0/8 port port=5432 protocol=tcp accept"
  }
}
```
Let a cluster's pod network in, by binding it to the trusted zone:

```hcl
step "pods" {
  firewalld {
    zone   = "trusted"
    source = "10.42.0.0/16"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks `firewall-cmd` whether the zone has the service, port, rich rule or source, once for the running firewall and once with `--permanent`. `in_sync` is true only when both allow it. A source is asked about with `--query-source`. firewalld keeps a source as written, so a network has to be written as its own address: `10.42.0.0/16`, not `10.42.0.1/16`. A source belongs to one zone only, so adding one that's already bound to another zone, running or permanent, fails the step and names that zone, rather than moving it. A rich rule is asked about with `--query-rich-rule`, which matches it however firewalld spells it back: `firewall-cmd --list-rich-rules` adds quotes, for one, so the text isn't compared. firewalld must be running: if it isn't, the step fails and asks you to install and start it in an earlier step.

**Applying.** Conn3x runs `firewall-cmd --add-service`, `--add-port`, `--add-rich-rule` or `--add-source`, then the same with `--permanent`, so the rule takes effect now and survives a reload or a reboot. Without `zone`, both go to firewalld's default zone.

**Confirming.** Removing the rule that lets SSH in can lock Conn3x out. So can adding a rich rule that rejects or drops, since firewalld checks those before the rules that accept: `rule family=ipv4 source address=0.0.0.0/0 service name=ssh reject` shuts out the next login, while the session already open carries on. So can binding the network Conn3x connects from to a zone that doesn't let SSH in, such as `drop` or `block`, since a source decides the zone before the interface does, or removing a source from `trusted` when SSH only got in through it. Give a change like those `confirm_after`. With `confirm_after`, the host schedules the commands that take the change back with `systemd-run`, due that long after, before Conn3x makes it. The undo is a timer in the host's own systemd, so it runs even if Conn3x goes away mid-apply. Conn3x then logs in again over a new connection with the circuit's whole `ssh` block, jump hosts and host key check included, and cancels the undo once that works. If the change fails, Conn3x takes it back at once. If the new login doesn't come in time, the host takes the change back by itself, and Conn3x fails the step saying whether the host answers again. The guard covers removing the step too, using the `confirm_after` the step had, and it only takes back what changed. `confirm_after` is between `10s` and `1h` and needs systemd on the host.

**Rules.** Set exactly one of `service`, `port`, `rich_rule` and `source`. A port takes a protocol, `tcp`, `udp`, `sctp` or `dccp`, and may be a range such as `60000-61000/udp`.

**Changes.** `zone`, `service` and `port` identify the rule, so changing any of them replaces the step. With the default `on_remove`, the old rule is removed from the firewall.

## Removal

When you delete a `firewalld` step, `on_remove` decides what happens on the host. The default is `"delete"`, unlike most modules: Conn3x removes the rule from the running and the permanent firewall, so a port you stop managing doesn't stay open. `"forget"` leaves it open.

## From Ansible

`conn3x convert ansible` turns `ansible.posix.firewalld` tasks that set `service`, `port`, `rich_rule` or `source` into `firewalld` steps. A task must set both `permanent: true` and `immediate: true`, since Conn3x always changes both; one that doesn't stays a TODO, as does a task with a `state` other than `enabled` or with any other argument, such as `interface`. A port given by service name, such as `http/tcp`, stays a TODO too: write the number, or use `service`. So does any task this step would refuse, such as one that sets both `service` and `port`.
