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

A BGP password goes in `lines_wo`, which state never keeps:

```hcl
step "peer" {
  vyos_config {
    lines    = ["set protocols bgp 65000 neighbor 192.0.2.1 remote-as 65001"]
    lines_wo = ["set protocols bgp 65000 neighbor 192.0.2.1 password use-an-ephemeral-variable-here"]
  }
}
```

<!-- reference -->

## Secrets in lines_wo

`lines_wo` is write-only, so a secret statement never lands in state or in the plan. State keeps two things instead: `lines_hmac`, an HMAC of the statements keyed outside state, and `lines_wo_prefixes`, each statement's path without its last word, such as `set protocols bgp 65000 neighbor 192.0.2.1 password`.

The router prints most secrets hashed or encrypted, so Conn3x can't compare them with yours. A refresh checks something smaller: that each path holds a value. If you change a secret, the HMAC changes and the plan shows an update; the apply deletes each path and sets your statements again. If you delete the statement by hand, the step shows as out of sync. But a secret changed by hand on the router still looks in sync, because the router can't show which secret it holds.

The secret has to be the statement's last word, after a keyword that ends in `password`, `secret` or `key`, such as `pre-shared-secret`. Two kinds of statement are refused. A plain-text password is refused because the router stores it hashed under another name, so it would never show as there. An SNMP community is refused because its name is its secret, so a path can't tell one community from another; use an SNMPv3 user instead. Each statement in `lines_wo` needs its own path, and no statement in `lines` can set one. In block mode, the paths count as wanted, so nothing under `prefix` that holds them is deleted.

Planning `lines_wo` needs the HMAC key, `CONN3X_HMAC_KEY` or `~/.config/conn3x/hmac.key`. Pass secrets through a variable file or `TF_VAR_`, not `-var`, since OpenTofu logs its command line. Rotation hasn't been tried on a real router yet, only against the test suite's fake one.

## Notes

- Log in as a user in the `vyattacfg` group, such as VyOS's own `vyos` user, with a key. `become` and `agent` are refused in the circuit's `ssh` block.
- Every line must be a `set` statement, so no line can leave configuration mode, commit early or run another command.
- Don't put secrets in `lines`: state keeps them as written, so a plan warns about a statement that ends in one. Use `lines_wo`. In logs and errors, Conn3x hides what follows `plaintext-password`, `encrypted-password`, `pre-shared-secret`, `secret`, `community` and `key`.
