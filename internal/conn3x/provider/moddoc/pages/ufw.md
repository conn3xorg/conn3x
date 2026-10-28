Use `ufw` to add a ufw rule for a port, on Debian and Ubuntu. Each step is one rule: an action, a port, and optionally the address it applies to. On the Red Hat family, use [`firewalld`](/modules/firewalld) instead.

## Example usage

Allow SSH, then HTTP and HTTPS:

```hcl
step "ssh" {
  ufw {
    action = "allow"
    port   = "22/tcp"
  }
}

step "web" {
  for_each = ["80/tcp", "443/tcp"]
  ufw {
    action = "allow"
    port   = item.value
  }
}
```

Allow a port from one network only:

```hcl
step "postgres" {
  ufw {
    action = "allow"
    port   = "5432/tcp"
    from   = "10.0.0.0/8"
  }
}
```

Rate-limit connections to a port:

```hcl
step "ssh_limit" {
  ufw {
    action = "limit"
    port   = "22/tcp"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x lists the rules with `ufw show added` and looks for this one. That works whether or not ufw is enabled.

**Applying.** Conn3x runs `ufw allow 22/tcp`, or `ufw allow from 10.0.0.0/8 to any port 5432 proto tcp` when you set `from`. ufw saves its rules, so they hold across reboots. ufw has no lock of its own, so Conn3x changes one rule at a time on each host and reads the rule back afterwards, failing the step if ufw didn't keep it.

**Enabling ufw.** Conn3x adds rules but doesn't enable ufw. Rules take effect once ufw is enabled. Allow SSH before you enable it, so the firewall doesn't cut off your SSH connection.

**Rules.** `action` is `allow`, `deny`, `reject` or `limit`. `port` is a port, optionally with `tcp` or `udp`; a range such as `6000:6007/tcp` needs the protocol. `from` is an IP address or a CIDR network.

**Changes.** `action`, `port` and `from` identify the rule, so changing any of them replaces the step. With the default `on_remove`, the old rule is deleted.

## Removal

When you delete a `ufw` step, `on_remove` decides what happens on the host. The default is `"delete"`, unlike most modules: Conn3x runs `ufw delete` for the rule, so a port you stop managing doesn't stay open. `"forget"` leaves the rule in place.

## From Ansible

`conn3x convert ansible` turns `community.general.ufw` tasks that set `rule` into `ufw` steps. `port` or `to_port` becomes `port`, with `proto` added unless it is `any`, and `from_ip`, `from` or `src` becomes `from`. A task without `rule`, which changes ufw itself, stays a TODO, as does a task with any other argument, such as `state`, `direction` or `comment`.
