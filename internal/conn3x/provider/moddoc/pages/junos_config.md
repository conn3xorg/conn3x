**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI, so try it on a lab device first.

Use `junos_config` to own a few statements of a Juniper Junos device's configuration: a description on an interface, an NTP server, a syslog host. You write each one as a set line, exactly as `show configuration | display set` prints it, and Conn3x leaves every other statement alone.

### How a change goes in

Junos answers every command with exit status 0, even one it refused, and a script can't stop halfway. So Conn3x sends each change twice.

1. **A dry run.** Your lines go into `configure private`, then `commit check`, then `rollback` and `exit`. If the device refuses a line, or the check fails, Conn3x stops there with the device's own words, and nothing has changed.
2. **The commit.** If the configuration still matches what Conn3x read for the plan, the same lines go into `configure exclusive` with `commit confirmed 5`. If someone else holds the configuration lock, Conn3x stops, and nothing has changed.
3. **The confirm.** Conn3x waits `confirm_after`, then logs in over a new SSH connection and runs `commit check`, which confirms. A change that locks Conn3x out never gets confirmed, so Junos rolls it back by itself within five minutes.

Junos refuses `commit confirmed` in private mode, which is why the commit uses `configure exclusive`. If the device refuses part of the change on the second pass, even though the dry run passed, Conn3x doesn't confirm, and the change rolls back by itself. The error says so. The same goes for a session that ends mid-commit: the commit may be what cut it, so Conn3x never claims nothing changed.

While a commit confirmed is waiting for its confirm, the lines it added may yet roll back. So a refresh counts the device's steps as out of sync, with a warning, and an apply stops before it sends anything. Apply again once the change has rolled back.

### The wait before the confirm

A change doesn't bite the moment it's committed, and a confirm sent too early would keep a change that's about to lock Conn3x out. So Conn3x waits `confirm_after`, 30 seconds unless you say otherwise. Set more in the circuit's `ssh` block for slower changes, such as firewall filters or routing:

```
ssh {
  user          = "ops"
  confirm_after = "90s"
}
```

It takes at least `"5s"` and anything under `"4m"`, so the confirm always lands before the five-minute rollback.

### One commit per device

In a circuit, a device's steps share one commit per apply. Each step works out its lines against the configuration plus what the steps before it added, and Conn3x runs the dry run over everything so far, so a refused line still fails the step that brought it. Nothing reaches the device until the last step is in. Then one commit confirmed, one wait and one confirm make the lot live together. Ten changed steps cost one `confirm_after`, not ten.

The plan shows two more lines per device, as with EOS. `conn3x_junos_commit.<circuit>__commit` changes only when one of the circuit's `junos_*` steps does. `conn3x_junos_removals.<circuit>__removals` does nothing until you destroy the circuit, and then it commits every removal in one go. A few things follow:

- If any step fails, everything the circuit staged for that device is dropped, and nothing of it reaches the device.
- A device holds one circuit's staged lines at a time. When two circuits have steps on the same device, the second one's steps wait until the first has committed, and give up after two minutes if the first goes quiet.
- A lockout rolls back the whole commit: every step of that apply on the device.
- `-target` on a single `junos_*` step leaves the commit out, and its lines are dropped when the run ends. Target `conn3x_junos_commit.<circuit>__commit` instead: it brings every step with it.
- A step outside a circuit, or one you take out of a circuit that stays, commits on its own.
- Conn3x forgets a removed step as soon as its removal is staged. So if the commit goes nowhere, Conn3x commits the removals on their own, and the error says so. Only if that fails too does the error list the lines for you to delete by hand.

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

A local account's hashed password goes in `lines_wo`, which state never keeps:

```hcl
step "ops_password" {
  junos_config {
    lines_wo = ["set system login user ops authentication encrypted-password use-an-ephemeral-variable-here"]
  }
}
```

<!-- reference -->

## Secrets in lines_wo

`lines_wo` is write-only, so a secret statement never lands in state or in the plan. State keeps two things instead: `lines_hmac`, an HMAC of the statements keyed outside state, and `lines_wo_prefixes`, each statement's path without its last word, such as `set system login user ops authentication encrypted-password`.

The device prints most secrets hashed or encrypted, so Conn3x can't compare them with yours. A refresh checks something smaller: that each path holds a value. If you change a secret, the HMAC changes and the plan shows an update; the apply deletes each path and sets your statements again. If you delete the statement by hand, the step shows as out of sync. But a secret changed by hand on the device still looks in sync, because the device can't show which secret it holds.

The secret has to be the statement's last word, after a keyword that ends in `password`, `secret` or `key`, or is `ascii-text` or `hexadecimal`. Two kinds of statement are refused. A plain-text password is refused because the device stores it hashed under another name, so it would never show as there. An SNMP community is refused because its name is its secret, so a path can't tell one community from another; use an SNMPv3 user instead. Each statement in `lines_wo` needs its own path, and no statement in `lines` can set one. In block mode, the paths count as wanted, so nothing under `prefix` that holds them is deleted.

Planning `lines_wo` needs the HMAC key, `CONN3X_HMAC_KEY` or `~/.config/conn3x/hmac.key`. Pass secrets through a variable file or `TF_VAR_`, not `-var`, since OpenTofu logs its command line. Rotation hasn't been tried on a real device yet, only against the test suite's fake one.

## Notes

- Log in as a user of class `super-user`, whose login starts in the CLI:

  ```
  set system login user ops class super-user
  set system login user ops authentication ssh-ed25519 "ssh-ed25519 AAAA..."
  ```

  `root` is refused, because its login starts in a shell. Junos has no sudo, so `become` and `agent` are refused in the circuit's `ssh` block too.
- A line Junos prints differently, such as one without the quotes `display set` adds, never matches, and the step shows as changed on every plan. Copy lines from `show configuration | display set`.
- Every line must be a `set` statement. Anything else could leave configuration mode, commit early or run another command. So `delete`, `exit`, `commit`, `run`, a `|` outside quotes, newlines and control characters are all refused. So is `plain-text-password`, which prompts for the password, and a script can't answer a prompt; set `encrypted-password` with a hash instead.
- A deactivated statement doesn't count as there, so a step that owns one shows as changed until it's activated.
- Don't put secrets in `lines`: state keeps them as written, so a plan warns about a statement that ends in one. Use `lines_wo`. In logs and errors, Conn3x hides what follows `encrypted-password`, `authentication-key`, `secret`, `community`, `pre-shared-key` and `key`.
- Commits on Junos persist, so there's no separate save step.

## From Ansible

`conn3x convert ansible` turns `junipernetworks.junos.junos_config` tasks into `junos_config` steps: `lines` (or its alias `commands`) carry over. Ansible's defaults, `match: line` and `update: merge`, are what this step does, so they need nothing. `save` becomes a note, since a Junos commit persists by itself; `confirm` becomes one too, since every change goes in under a revert timer; and `backup` becomes a note to set `device_backup_dir` on the circuit. `src`, any other `update`, and a line that isn't a `set` statement, `delete` lines included, stay TODOs. A play whose tasks are all network modules takes `connection: network_cli` without a TODO.
