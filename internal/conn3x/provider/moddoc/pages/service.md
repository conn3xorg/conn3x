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
<!-- reference -->
## How it works

**Reading.** Every plan asks systemd for the unit's state with `systemctl show`. A unit that is active, activating or reloading counts as running, and a unit file state that starts with `enabled` counts as enabled.

**Names.** A `name` without a dot gets `.service` added, so `"nginx"` means `nginx.service`.

**Applying.** Conn3x runs `systemctl enable` or `disable`, then `start` or `stop`, and only for what differs. If the unit file changed since systemd last loaded it, or systemd can't find the unit, Conn3x runs `systemctl daemon-reload` first. After applying, Conn3x reads the unit again and fails the step if it didn't reach the state you asked for; `systemctl status` on the host shows why.

**What's left alone.** Leave out `state` and the step doesn't start or stop the unit. Leave out `enabled` and it doesn't change what happens at boot. With both left out, the step only checks that the unit exists.

**Missing units.** The unit has to exist on the host. Install its package in an earlier step; steps run in the order written.

**Restarts.** A `service` step never restarts a unit that is already running. When a configuration file changes, notify a handler, which runs `systemctl restart`, or `systemctl reload` with `action = "reload"`, after the circuit's steps.

## Removal

When you delete a `service` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the unit as it is. `"delete"` stops it and disables it. The unit file stays.

## From Ansible

`conn3x convert ansible` turns `service`, `systemd` and `systemd_service` tasks with `state: started` or `stopped`, or with `enabled`, into `service` steps. `daemon_reload` is dropped, since Conn3x reloads systemd when a unit file changed. A task with `state: restarted` or `reloaded` stays a TODO. A handler that does nothing but restart or reload a service becomes a Conn3x handler, and `notify` carries over.
