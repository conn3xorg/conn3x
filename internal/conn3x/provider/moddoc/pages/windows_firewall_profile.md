Use `windows_firewall_profile` to turn a Windows Firewall profile on or off, and to set what it does with traffic no rule matches. Use one step per profile. Rules themselves are [`windows_firewall_rule`](/modules/windows_firewall_rule).

## Example usage

Let SSH in, then turn the Public profile on with inbound blocked:

```hcl
step "ssh_in" {
  windows_firewall_rule {
    name        = "OpenSSH-Server-In-TCP"
    protocol    = "tcp"
    local_ports = ["22"]
  }
}
```

```hcl
step "public" {
  windows_firewall_profile {
    name             = "public"
    enabled          = true
    default_inbound  = "block"
    default_outbound = "allow"
  }
}
```
<!-- reference -->
## How it works

`name` is `domain`, `private` or `public`. `enabled`, `default_inbound` and `default_outbound` are each left as they are when unset, and a step has to set at least one.

**Reading.** On every plan, Conn3x reads the profile with `Get-NetFirewallProfile`. `in_sync` is true when it has every setting the step sets. `NotConfigured` reads as Windows' default: on, inbound blocked, outbound allowed.

**Applying.** Conn3x runs `Set-NetFirewallProfile` with the settings the step sets, then reads them back. Settings Group Policy fixes can't be changed locally, so the step fails and says Group Policy may set them.

**The lockout check.** A change that leaves the profile on with inbound blocked, where it wasn't, can stop Conn3x's next login. So before making it, Conn3x reads the connection it's on from `SSH_CONNECTION`, which gives the client's address and sshd's own port, and every enabled inbound rule in force, Group Policy's included. It refuses the change unless:
- the connection is over loopback, which Windows Firewall doesn't filter; or
- the connection came in on a network in another profile; or
- an allow rule in this profile surely lets the connection in, and no block rule matches it.

To surely let it in, an allow rule has to be for TCP, or any protocol, to sshd's port, and for any program or sshd itself, and any service or `sshd`. Its remote addresses have to be `Any`, or include the client's address. `LocalSubnet` doesn't count, since Conn3x may come through a VPN, NAT or a jump host from outside the subnet.

A block rule that matches the connection beats any allow rule, as in Windows Firewall, so that refuses too. When sshd doesn't report the client's address, only an allow rule from any address counts.

Turning a profile off, allowing inbound, and changing outbound are never refused. Unlike the Linux firewall steps, there's no `confirm_after` here, so let SSH in with a `windows_firewall_rule` step first.

## Removal

Deleting a `windows_firewall_profile` step leaves the profile as it is.

## From Ansible

`conn3x convert ansible` turns `community.windows.win_firewall` tasks into `windows_firewall_profile` steps, one for each profile in `profiles`, which defaults to all three, as it does in Ansible. `state: enabled` or `disabled` becomes `enabled`, and `inbound_action` and `outbound_action` become `default_inbound` and `default_outbound`. `not_configured`, which hands an action back to the default, stays a TODO, and so does a task that sets nothing.
