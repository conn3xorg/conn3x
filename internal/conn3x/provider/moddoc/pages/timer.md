Use `timer` to run a command on a schedule with systemd. Each step writes a oneshot service and a timer that starts it, then enables and starts the timer. Compared with [`cron`](/modules/cron), the job's output goes to the journal, and a timer can run a job it missed while the host was off.

## Example usage

Run a backup at 02:30 every night, and catch up at boot if the host was off:

```hcl
step "backup" {
  timer {
    name        = "backup"
    on_calendar = "*-*-* 02:30:00"
    command     = "/usr/local/bin/backup --quiet"
    persistent  = true
  }
}
```

Run a job as another user, with a description that `systemctl status` shows:

```hcl
step "report" {
  timer {
    name        = "app-report"
    on_calendar = "Mon *-*-* 06:00:00"
    user        = "app"
    command     = "/opt/app/bin/report --weekly"
    description = "Weekly app report"
  }
}
```
<!-- reference -->
## How it works

**The units.** Conn3x writes `/etc/systemd/system/<name>.service`, with `Type=oneshot`, `User` and `ExecStart`, and `/etc/systemd/system/<name>.timer`, with `OnCalendar`, `Persistent` and `WantedBy=timers.target`. Both are owned by root with mode `0644`. The command runs as `root` unless you set `user`. Without `description`, the units are described as `<name> (managed by Conn3x)`.

**Applying.** After writing the units, Conn3x runs `systemctl daemon-reload` if they are new or changed, then enables and starts `<name>.timer`.

**Commands.** systemd runs `command` directly, not through a shell. For pipes or redirection, use `sh -c '...'`. Conn3x escapes `%` as `%%`, so a `%` in `command` or `description` reaches the program as written.

**Reading.** Every plan reads both unit files and asks systemd whether the timer is enabled and running. If a unit was edited, or the timer was stopped or disabled, the plan shows the step out of sync and the next apply puts it back.

**Validation.** `name` is the unit name without `.timer` or `.service`. `on_calendar` and `command` must each be a single line. Conn3x checks these before connecting to the host.

## Removal

When you delete a `timer` step, `on_remove` decides what happens on the host. The default, `"delete"`, stops and disables the timer, removes both unit files and reloads systemd. `"forget"` leaves the timer running.
