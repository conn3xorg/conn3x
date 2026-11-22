**Experimental.** Network devices are new, and this module may change between releases. It's tested against IOS XE 17.18 (IOL-XE) and classic IOS 15.9 (IOSv) in Cisco Modeling Labs on a lab VM, not yet in CI and not on hardware, so try it on a lab device first.

Use `ios_config` to own a few lines of a Cisco IOS XE device's running configuration: a description on an interface, an NTP server, a logging host. You write each line the way `show running-config` prints it, under the blocks it sits in, and Conn3x leaves every other line alone.

### Before the first change: an archive

IOS has no candidate configuration. A line is live the moment it's typed, and a line IOS refuses doesn't stop the ones after it. What makes a change safe is the revert timer, and the timer needs somewhere to keep the configuration it rolls back to. So Conn3x won't change a device without a configuration archive, and says so:

```
archive
 path flash:conn3x
 maximum 5
```

On IOL, which has no `flash:`, it's `path unix:conn3x`.

### How a change goes in

1. **The checks.** Conn3x reads `show archive` for a path and `show archive config rollback timer` for a change already waiting. If either says no, it stops, and nothing has changed.
2. **The change.** If the configuration still matches what Conn3x read for the plan, the lines go in under `configure terminal revert timer 5`. IOS archives the running configuration first, then takes the lines.
3. **A refusal.** If IOS refused any line, with `% Invalid input` or any other `%` message, Conn3x runs `configure revert now` at once. Everything the change typed comes back out, and the step fails with the device's own words.
4. **The confirm.** Otherwise Conn3x waits `confirm_after`, then logs in over a new SSH connection, runs `configure confirm`, and saves with `write memory`. A change that locks Conn3x out never gets confirmed, so IOS rolls it back by itself within five minutes.

While a change is waiting for its confirm, a refresh counts the device's steps as out of sync, and an apply stops before it types anything. IOS would take new lines then, but they'd roll back with the other change.

### Logging in

Log in as a user with privilege 15, so the session starts at `#`, with an SSH key:

```
username ops privilege 15 secret 0 <a long random secret>
ip ssh pubkey-chain
 username ops
  key-string
   <your public key>
```

IOS XE 17 takes Conn3x's SSH defaults. Classic IOS, such as IOS 15.9, only offers SHA-1 SSH, which Conn3x refuses by default: set `legacy_algorithms = true` on that device's host object, and it applies to that host only, never a jump host. Classic IOS also prints access-list entries without their sequence numbers, so write them without, the way `show running-config` shows them.

### One commit per device

In a circuit, a device's steps share one change per apply, as on Junos: each step works out its lines from the configuration plus what the steps before it added, and one revert timer, one wait and one confirm make the lot live together. The plan shows `conn3x_ios_commit.<circuit>__commit` and `conn3x_ios_removals.<circuit>__removals` for each device. A step outside a circuit changes the device on its own.

## Example usage

```hcl
step "uplink" {
  ios_config {
    parents = ["interface GigabitEthernet1"]
    lines   = ["description uplink to core"]
  }
}

step "ntp" {
  ios_config {
    lines = ["ntp server 192.0.2.10"]
  }
}
```

Own a whole block with `match = "block"`: lines under it that aren't listed are removed with their `no` form.

```hcl
step "mgmt_acl" {
  ios_config {
    parents = ["ip access-list standard MGMT"]
    lines   = ["10 permit 192.0.2.0 0.0.0.255"]
    match   = "block"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads `show running-config` and finds the block `parents` name. `in_sync` is true when every line is there, and with `match = "block"`, when nothing else is.

**A line must read back as you wrote it.** IOS often rewrites a line: abbreviations come back in full, and some defaults never show at all. A line that reads back differently never shows as in sync, so copy it from `show running-config`.

**Changes.** Changing `lines` or `match` updates the device in place. Changing `parents` is a different block, so it replaces the step.

**What's refused.** A line that would leave configuration mode or act outside it, such as `end`, `exit`, `do`, `write`, `copy` or a short form of them, or one with a leading space, a newline or a control character. Conn3x enters configuration mode, confirms and saves on its own.

## Removal

`on_remove = "forget"`, the default, leaves the lines. `on_remove = "delete"` removes each line with its `no` form, and leaves the parent blocks.

## From Ansible

`conn3x convert ansible` turns `cisco.ios.ios_config` tasks into `ios_config` steps: `lines` (or its alias `commands`) and `parents` carry over. Ansible's defaults, `match: line` and `replace: line`, are what this step does, so they need nothing. `save_when` becomes a note, since Conn3x saves the running configuration after every change; `confirm` becomes one too, since every change goes in under a revert timer; and `backup` becomes a note to set `device_backup_dir` on the circuit. `src`, any other `match` or `replace`, and a line with `prompt` and `answer` stay TODOs. `become` stays a TODO too, since IOS refuses it: log in as a user whose session starts at `#`. A play whose tasks are all network modules takes `connection: network_cli` without a TODO.
