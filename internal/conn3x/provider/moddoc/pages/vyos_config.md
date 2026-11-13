**Experimental.** Network devices are new, and this module may change between releases. It's tested against VyOS 2026.11.13-0016-rolling in a container on a lab VM, not yet in CI, so try it on a lab router first.

Use `vyos_config` to own a few statements of a VyOS router's configuration: a static route, an NTP server, a firewall rule. You write each one as a set line, the way `show configuration commands` prints it, and Conn3x leaves every other statement alone. Quotes don't matter: `'uplink'`, `"uplink"` and `uplink` are the same value.

### How a change goes in

VyOS lets a script carry on past a refused line, and a later `commit` in the same script still commits the rest. So Conn3x sends each change twice, as it does on Junos:

1. **A dry run.** Your lines go into `configure`, then `compare`, then `exit discard`. If the router refuses a line (`Set failed`), Conn3x stops there with the router's own words, and nothing has changed.
2. **The commit.** If the configuration still matches what Conn3x read for the plan, the same lines go in with `commit-confirm 5`, and Conn3x answers its question.
3. **The confirm.** After `confirm_after`, 30 seconds unless you say otherwise, Conn3x logs in again over a new SSH connection, runs `confirm`, and saves. A change that locks Conn3x out never gets confirmed, so VyOS rolls it back by itself within five minutes.

While a commit-confirm waits for its confirm, a refresh counts the router's steps as out of sync, and an apply stops before it sends anything.

### Reload, not reboot

By default, VyOS undoes an unconfirmed commit by **rebooting**. That still gets rid of a change that locked you out, but it takes the router down to do it. Have it reload the previous configuration instead:

```
set system config-management commit-confirm action reload
```

Until it says `reload`, every refresh of a `vyos_*` step warns.

### One commit per router

In a circuit, a router's steps share one commit per apply, as on Junos and EOS. Each step's dry run covers what the steps before it staged, so a refused line still fails the step that brought it. The plan shows `conn3x_vyos_commit.<circuit>__commit` and `conn3x_vyos_removals.<circuit>__removals`, which work as they do for [Junos](/modules/junos_config).

## Example usage

```hcl
step "routes" {
  vyos_config {
    lines = [
      "set protocols static route 0.0.0.0/0 next-hop 192.0.2.1",
      "set service ntp server 0.pool.ntp.org",
    ]
  }
}
```

<!-- reference -->

## Notes

- Log in as a user in the `vyattacfg` group, such as VyOS's own `vyos` user, with a key. `become` and `agent` are refused in the circuit's `ssh` block.
- Every line must be a `set` statement, so no line can leave configuration mode, commit early or run another command.
- Don't put secrets in `lines`: they'd be stored in state. In logs and errors, Conn3x hides what follows `plaintext-password`, `encrypted-password`, `pre-shared-secret`, `secret`, `community` and `key`.
