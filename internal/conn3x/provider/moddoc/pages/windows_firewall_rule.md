**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_firewall_rule` to open, or close, a port in Windows Firewall. The rule is found by its name, so Conn3x changes the one rule it made and leaves the others alone.

## Example usage

```hcl
step "https_in" {
  windows_firewall_rule {
    name        = "Conn3x HTTPS"
    protocol    = "tcp"
    local_ports = ["443"]
  }
}
```

```hcl
step "sql_from_app_subnet" {
  windows_firewall_rule {
    name             = "SQL from app subnet"
    protocol         = "tcp"
    local_ports      = ["1433"]
    remote_addresses = ["10.20.0.0/24"]
    profiles         = ["domain", "private"]
  }
}
```
<!-- reference -->
## How it works

Every setting you leave out takes its default, so a rule changed by hand shows as drift. Two are left as they are when unset: `description`, and `display_name`, so naming a rule Windows made doesn't rename it. Subnets are compared the way Windows stores them: `10.0.0.0/8` and `10.0.0.0/255.0.0.0` are the same.

`name` is the rule's ID, not the name shown in Windows' tools, which is `display_name`. Rules made by Windows or another tool have their own IDs, such as `OpenSSH-Server-In-TCP`; naming one here lets Conn3x manage it.

**Getting locked out.** Before it changes or deletes a rule, Conn3x asks the host which connection it's on, from sshd's `SSH_CONNECTION`: your address and sshd's own port, which NAT can hide from the configuration. It refuses a rule that would block that connection, since block rules beat allow rules, and refuses to delete, disable or narrow a rule that lets it in. So deleting the step for such a rule fails until you set `on_remove = "forget"`. A rule kept for SSH must name your address outright: `LocalSubnet` doesn't count, as you may come through a VPN, NAT or a jump host. If sshd doesn't report the connection, Conn3x refuses any block on the SSH port and any change to a rule that lets it in. It looks at one rule at a time, so it refuses even when another rule would still let you in. It can't see a firewall policy from a domain, and a rule a group policy sets can't be changed here.

## Removal

By default, deleting a `windows_firewall_rule` step deletes the rule. With `on_remove = "forget"` the rule stays.
