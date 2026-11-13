**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI, so try it on a lab device first.

Use `junos_config` to own a few statements of a Juniper Junos device's configuration: a description on an interface, an NTP server, a syslog host. You write each one as a set line, exactly as `show configuration | display set` prints it, and Conn3x leaves every other statement alone.

### How a change goes in

Junos answers every command with exit status 0, even one it refused, and a script can't stop halfway. So Conn3x sends each change twice.

1. **A dry run.** Your lines go into `configure private`, then `commit check`, then `rollback` and `exit`. If the device refuses a line, or the check fails, Conn3x stops there with the device's own words, and nothing has changed.
2. **The commit.** If the configuration still matches what Conn3x read for the plan, the same lines go into `configure exclusive` with `commit confirmed 5`. If someone else holds the configuration lock, Conn3x stops, and nothing has changed.
3. **The confirm.** Conn3x waits `confirm_after`, then logs in over a new SSH connection and runs `commit check`, which confirms. A change that locks Conn3x out never gets confirmed, so Junos rolls it back by itself within five minutes.

Junos refuses `commit confirmed` in private mode, which is why the commit uses `configure exclusive`. If the device refuses part of the change on the second pass, even though the dry run passed, Conn3x doesn't confirm, and the change rolls back by itself. The error says so.

### The wait before the confirm

A change doesn't bite the moment it's committed, and a confirm sent too early would keep a change that's about to lock Conn3x out. So Conn3x waits `confirm_after`, 30 seconds unless you say otherwise. Set more in the circuit's `ssh` block for slower changes, such as firewall filters or routing:

```
ssh {
  user          = "ops"
  confirm_after = "90s"
}
```

It takes at least `"5s"` and anything under `"4m"`, so the confirm always lands before the five-minute rollback. For now each step commits on its own, so a device with three changed steps pays the wait three times.

## Example usage

```hcl
step "uplink" {
  junos_config {
    lines = [
      "set interfaces ge-0/0/1 description \"uplink to core\"",
      "set interfaces ge-0/0/1 mtu 9216",
    ]
  }
}
```

With `match = "block"`, the statements under `prefix` must be exactly these, and any other statement under it is deleted:

```hcl
step "ntp" {
  junos_config {
    prefix = "system ntp"
    match  = "block"
    lines = [
      "set system ntp server 10.0.0.1",
      "set system ntp server 10.0.0.2",
    ]
  }
}
```

<!-- reference -->

## Notes

- Log in as a user of class `super-user`, whose login starts in the CLI:

  ```
  set system login user ops class super-user
  set system login user ops authentication ssh-ed25519 "ssh-ed25519 AAAA..."
  ```

  `root` is refused, because its login starts in a shell. Junos has no sudo, so `become` and `agent` are refused in the circuit's `ssh` block too.
- A line Junos prints differently, such as one without the quotes `display set` adds, never matches, and the step shows as changed on every plan. Copy lines from `show configuration | display set`.
- Every line must be a `set` statement. Anything else could leave configuration mode, commit early or run another command. So `delete`, `exit`, `commit`, `run`, a `|` outside quotes, newlines and control characters are all refused.
- A deactivated statement doesn't count as there, so a step that owns one shows as changed until it's activated.
- Don't put secrets in `lines`: they'd be stored in state. In logs and errors, Conn3x hides what follows `encrypted-password`, `authentication-key`, `secret`, `community`, `pre-shared-key` and `key`.
- Commits on Junos persist, so there's no separate save step.
