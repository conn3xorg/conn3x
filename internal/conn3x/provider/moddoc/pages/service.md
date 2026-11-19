Use `service` to keep a systemd unit running or stopped, and to choose whether it starts at boot. To restart or reload a service when a file it reads changes, use a [handler](/concepts#handlers).

## Example usage

Start a service now and at every boot:

```hcl
step "nginx" {
  service {
    name    = "nginx"
    state   = "started"
    enabled = true
  }
}
```

Stop a service and keep it from starting at boot:

```hcl
step "no_cups" {
  service {
    name    = "cups"
    state   = "stopped"
    enabled = false
  }
}
```

Manage a unit that isn't a service, such as a timer or a socket, by giving its full name:

```hcl
step "fstrim" {
  service {
    name    = "fstrim.timer"
    state   = "started"
    enabled = true
  }
}
```
Keep a unit from ever starting, as hardening baselines do for `rpcbind` or `avahi-daemon`, even before its package is installed:

```hcl
step "no_rpcbind" {
  service {
    name   = "rpcbind"
    state  = "stopped"
    masked = true
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan asks systemd for the unit's state with `systemctl show`. A unit that is active, activating or reloading counts as running, and a unit file state that starts with `enabled` counts as enabled.

**Names.** A `name` without a dot gets `.service` added, so `"nginx"` means `nginx.service`.

**Applying.** Conn3x runs `systemctl enable` or `disable`, then `start` or `stop`, and only for what differs. If the unit file changed since systemd last loaded it, or systemd can't find the unit, Conn3x runs `systemctl daemon-reload` first. After applying, Conn3x reads the unit again and fails the step if it didn't reach the state you asked for; `systemctl status` on the host shows why.

**What's left alone.** Leave out `state` and the step doesn't start or stop the unit. Leave out `enabled` and it doesn't change what happens at boot. With both left out, the step only checks that the unit exists.

**Masking.** `masked = true` runs `systemctl mask`, which links the unit to `/dev/null` in `/etc/systemd/system`, so nothing can start it, not even a unit that wants it. It works on a unit that isn't installed, and runs before `state`, so `state = "stopped"` stops a masked unit that was running. `masked = false` runs `systemctl unmask`. A mask leaves an enabled unit's boot links in place, so unmasking brings it back enabled. To keep it off when it's unmasked later, set `enabled = false` with the mask: the step disables the unit first, while systemd still reports it enabled. A masked unit can't be started or enabled, so `masked = true` with `state = "started"` or `enabled = true` fails when you validate. systemd refuses to mask a unit that has its own file in `/etc/systemd/system`, rather than in `/usr/lib/systemd/system` where packages put theirs, and the step fails with systemd's message. A unit reads as masked when systemd says it's masked, so `is_masked` shows it.

**Missing units.** The unit has to exist on the host, unless the step masks it. Install its package in an earlier step; steps run in the order written.

**Restarts.** A `service` step never restarts a unit that is already running. When a configuration file changes, notify a handler, which runs `systemctl restart`, or `systemctl reload` with `action = "reload"`, after the circuit's steps. A unit that isn't running is started instead of reloaded, since systemd can't reload it, as Ansible's `reloaded` does.

## Removal

When you delete a `service` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the unit as it is. `"delete"` stops it and disables it. The unit file stays.

## From Ansible

`conn3x convert ansible` turns `service`, `systemd` and `systemd_service` tasks with `state: started` or `stopped`, or with `enabled`, into `service` steps, and `masked` carries over. `daemon_reload` is dropped, since Conn3x reloads systemd when a unit file changed. A task with `state: restarted` or `reloaded` stays a TODO. A handler that does nothing but restart or reload a service becomes a Conn3x handler, and `notify` carries over.
