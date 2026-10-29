Use `cron` to run a command on a schedule with the host's cron daemon. Each step is one job in its own file in `/etc/cron.d`, so jobs don't touch anyone's crontab. For a job that logs to the journal or catches up after downtime, use [`timer`](/modules/timer).

## Example usage

Run a backup at 02:30 every night:

```hcl
step "backup" {
  cron {
    name     = "backup"
    schedule = "30 2 * * *"
    command  = "/usr/local/bin/backup --quiet"
  }
}
```

Run a job as another user, with a macro for the schedule:

```hcl
step "cleanup" {
  cron {
    name     = "app-cleanup"
    schedule = "@hourly"
    user     = "app"
    command  = "find /var/lib/app/tmp -type f -mmin +60 -delete"
  }
}
```

Install the cron daemon first on a minimal Red Hat family host, where it may be missing:

```hcl
step "cronie" {
  package {
    name = "cronie"
  }
}

step "stamp" {
  cron {
    name     = "stamp"
    schedule = "@daily"
    command  = "date +%F >> /var/log/stamp"
  }
}
```
<!-- reference -->
## How it works

**The file.** Conn3x writes `/etc/cron.d/<name>`, owned by root with mode `0644`. It sets `SHELL=/bin/sh` and a standard `PATH`, then the job line, which runs as `root` unless you set `user`.

**Percent signs.** cron turns an unescaped `%` into a newline, so Conn3x escapes every `%` in `command` for you. Write `date +%F`, not `date +\%F`.

**Reading.** Every plan reads the file and compares it with what the step would write. If someone edited or removed it, the plan shows the step out of sync and the next apply writes it again.

**Validation.** `name` may use only letters, digits, `-` and `_`, since cron ignores files in `/etc/cron.d` with other names. `schedule` must be five fields or one of `@reboot`, `@yearly`, `@annually`, `@monthly`, `@weekly`, `@daily`, `@midnight` and `@hourly`. `command` must be a single line. Conn3x checks these before connecting to the host.

**Distro differences.** The cron daemon is `cronie` on the Red Hat family and `cron` on Debian and Ubuntu. If `/etc/cron.d` doesn't exist, the step fails and asks you to install it.

## Removal

When you delete a `cron` step, `on_remove` decides what happens on the host. The default, `"delete"`, removes the file, so the job stops running. `"forget"` leaves it.

## From Ansible

`conn3x convert ansible` turns `cron` tasks into `cron` steps. `minute`, `hour`, `day`, `month` and `weekday` become `schedule`, with `*` for any you leave out, and `special_time` becomes a macro such as `@daily`. `job` becomes `command`, and the task's `name` becomes the file name, with other characters replaced by `-`. The job moves from the user's crontab to `/etc/cron.d`, so the step comes with a TODO to delete the old crontab line, or the job runs twice. A task with `cron_file` or `state: absent` stays a TODO.
