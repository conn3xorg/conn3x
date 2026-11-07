**Experimental.** Network devices are new, and this module may change between releases. It's tested against cEOS-lab 4.37.0F on a local machine, not yet in CI, so try it on a lab switch first.

Use `eos_config` to own a few lines of an Arista EOS switch's configuration: a description on an interface, a neighbor under BGP, a banner. You write each line the way `show running-config` prints it, without the indent, and Conn3x leaves every other line alone.

Every change goes through a named EOS config session. If the switch refuses any line, the session is aborted and nothing changes. If it takes them all, Conn3x commits with a five-minute revert timer, waits, and then confirms the commit over a new SSH login. A change that locks Conn3x out never gets confirmed, so the switch rolls it back by itself. Once confirmed, the running config is saved to startup-config.

### Why it waits before confirming

A change doesn't bite the moment it's committed. On cEOS-lab, turning off SSH took 3 to 6 seconds to stop new logins. Confirm inside that gap and the login still works, so Conn3x would keep a change that's about to lock it out. So it waits `confirm_after` first, 30 seconds unless you say otherwise, and only then tries the new login.

That wait is paid once per step today, so a switch with ten steps takes about five minutes longer to apply. Slower changes, such as ACLs, VRF moves, AAA, or anything on real hardware, may need longer than 30 seconds to take effect; set more in the circuit's `ssh` block:

```
ssh {
  user          = "ops"
  confirm_after = "90s"
}
```

It takes at least `"5s"` and anything under `"4m"`, so the confirm always lands before the five-minute revert. One session per switch per apply, which pays the wait once, is coming in a later release.

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

- The login has to start in privileged mode. Give the user privilege 15 and let EOS honour it at login:

  ```
  username ops privilege 15 role network-admin
  username ops ssh-key ssh-ed25519 AAAA...
  aaa authorization exec default local
  ```

  Conn3x never types `enable`: on a switch with an enable password, `enable` would read the next line of the change as the password. Without the `aaa` line, every step fails and says so.
- EOS has no shell and no sudo, so `become` and `agent` are refused in the circuit's `ssh` block. Log in with a key; password login isn't supported yet.
- A line the switch rewrites, such as `int et1` for `interface Ethernet1`, never matches, and the step shows as changed on every plan. Copy lines from `show running-config`.
- Don't put secrets in `lines`: they'd be stored in state. Write-only lines are planned for a later release.
