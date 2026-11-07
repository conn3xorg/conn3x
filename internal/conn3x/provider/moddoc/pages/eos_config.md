**Experimental.** Network devices are new, this module may change between releases, and it hasn't yet run against a switch in our CI. Try it on a lab switch first.

Use `eos_config` to own a few lines of an Arista EOS switch's configuration: a description on an interface, a neighbor under BGP, a banner. You write each line the way `show running-config` prints it, without the indent, and Conn3x leaves every other line alone.

Every change goes through a named EOS config session. If the switch refuses any line, the session is aborted and nothing changes. If it takes them all, Conn3x commits with a five-minute revert timer, then confirms the commit over a new SSH login. A change that locks Conn3x out never gets confirmed, so the switch rolls it back by itself. Once confirmed, the running config is saved to startup-config.

## Example usage

```hcl
step "uplink" {
  eos_config {
    parents = ["interface Ethernet1"]
    lines = [
      "description uplink to core",
      "switchport mode trunk",
    ]
  }
}
```

With `match = "block"`, the block must be exactly these lines, and any other line under it is removed:

```hcl
step "mgmt_acl" {
  eos_config {
    parents = ["ip access-list MGMT"]
    match   = "block"
    lines = [
      "10 permit ip 10.0.0.0/24 any",
      "20 deny ip any any",
    ]
  }
}
```

<!-- reference -->

## Notes

- Log in as a user with privilege 15, such as one made with `username ops privilege 15 role network-admin`. EOS has no shell and no sudo, so `become` and `agent` are refused in the circuit's `ssh` block.
- A line the switch rewrites, such as `int et1` for `interface Ethernet1`, never matches, and the step shows as changed on every plan. Copy lines from `show running-config`.
- Don't put secrets in `lines`: they'd be stored in state. Write-only lines are planned for a later release.
