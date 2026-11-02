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

Every setting you leave out takes its default, so a rule changed by hand, in any setting except `description`, shows as drift. Subnets are compared the way Windows stores them: `10.0.0.0/8` and `10.0.0.0/255.0.0.0` are the same.

`name` is the rule's ID, not the name shown in Windows' tools, which is `display_name`. Rules made by Windows or another tool have their own IDs, such as `RemoteDesktop-UserMode-In-TCP`; naming one here lets Conn3x manage it.

**Getting locked out.** Conn3x refuses a rule that blocks inbound TCP to its own SSH port from anywhere, since block rules beat allow rules in Windows Firewall. It can't see every route to that, such as a firewall policy from a domain. A rule a group policy sets can't be changed here, and apply says so.

## Removal

By default, deleting a `windows_firewall_rule` step deletes the rule. With `on_remove = "forget"` the rule stays.
