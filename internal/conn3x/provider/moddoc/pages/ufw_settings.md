Use `ufw_settings` to turn ufw on or off and set its default policies, on Debian and Ubuntu. A host has one: [`ufw`](/modules/ufw) steps add the rules, and this step decides whether they apply and what happens to traffic no rule matches.

## Example usage

Allow SSH, refuse everything else coming in, and turn ufw on:

```hcl
step "ssh" {
  ufw {
    action = "allow"
    port   = "22/tcp"
  }
}

step "firewall" {
  ufw_settings {
    enabled          = true
    default_incoming = "deny"
    default_outgoing = "allow"
  }
}
```

Guard the change, so the host turns ufw back off by itself if Conn3x can't log in again:

```hcl
step "firewall" {
  ufw_settings {
    enabled          = true
    default_incoming = "deny"
    confirm_after    = "60s"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the default policies from `/etc/default/ufw` and whether ufw is on from `ufw status` and `/etc/ufw/ufw.conf`. ufw counts as on only when it's running and enabled at boot. `ufw status` shows no policies while ufw is off, and shows routed as disabled while the host doesn't forward, so the file is what Conn3x compares. A setting you leave out is left as it is, and not compared.

**Applying.** Conn3x runs `ufw default deny incoming` and the like for each policy that differs, then `ufw --force enable` or `ufw disable`. That way, ufw comes up with its policies already in place. The step reads ufw back afterwards and fails if it doesn't match.

**Not locking you out.** Turning ufw on with incoming traffic refused, or refusing incoming traffic while it's on, cuts off every port no rule allows, SSH included. So Conn3x reads the ports sshd listens on from `sshd -T`, which are the host's own ports even behind port forwarding. If no `ufw` rule allows or limits one of them, the step refuses before anything changes. A rule with `from` counts, since where you log in from is your call, and so does the `OpenSSH` application profile when sshd is on port 22. Put the `ufw` step that allows SSH before this one.

**Confirming.** With `confirm_after`, the lockout check is skipped, and the change is guarded instead, as rules are. Before the change, the host schedules its own undo with `systemd-run`: the old policies, and ufw back off if it was off. After the change, Conn3x logs in again over a new connection and cancels the undo. If that login doesn't come in time, the host takes the change back by itself. `confirm_after` is between `10s` and `1h` and needs systemd.

**Settings.** `enabled` is `true` or `false`. `default_incoming`, `default_outgoing` and `default_routed` are each `allow`, `deny` or `reject`. A step has to set at least one of them.

## Removal

Deleting a `ufw_settings` step leaves ufw as it is: on or off, with the policies it had.

## From Ansible

`conn3x convert ansible` turns a `community.general.ufw` task without `rule` into a `ufw_settings` step:
- `state: enabled` or `disabled` becomes `enabled`.
- `default`, or its alias `policy`, becomes `default_incoming`, `default_outgoing` or `default_routed` by `direction`. Without `direction` it's incoming, as Ansible reads it.

`state: reloaded` and `reset`, `logging`, and `direction: in` or `out` with `default`, which Ansible refuses, stay TODOs.
