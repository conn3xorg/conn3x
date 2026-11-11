Use `crontab` to own the whole of one user's crontab, the one `crontab -e` edits: the step lists every job and environment line, and Conn3x removes anything else. It's for "only these jobs run as deploy". To add one job without owning the rest, use a [`cron`](/modules/cron) step, which keeps each job in its own file in `/etc/cron.d`.

## Example usage

The whole of `deploy`'s crontab: two jobs, and where their mail goes:

```hcl
step "deploy_cron" {
  crontab {
    user = "deploy"
    env  = { MAILTO = "ops@example.com" }

    job {
      name     = "backup"
      schedule = "0 3 * * *"
      command  = "/opt/app/bin/backup"
    }

    job {
      name     = "warm-cache"
      schedule = "@reboot"
      command  = "/opt/app/bin/warm"
    }
  }
}
```

An empty crontab for an account that should run nothing:

```hcl
step "www_no_cron" {
  crontab {
    user = "www-data"
  }
}
```
<!-- reference -->
## How it works

**What it writes.** Conn3x writes the crontab with `crontab -u <user> -`, so the crontab command keeps the spool file, as it does for `crontab -e`. In the crontab:
- **Kept comments:** comments and blank lines that were already there come first, in their order.
- **Environment:** then the `env` lines, by name.
- **Jobs:** then each job, under a `# conn3x: <name>` comment.

A `%` in a command is written as `\%`, so cron passes it on as a `%` and doesn't turn it into a newline.

**What it removes.** Any other line goes, and the plan shows it:
- a job the step doesn't list;
- an environment line that isn't in `env`, or has another value;
- a line Conn3x can't read as either, since cron might still run it.

**The plan.** Every plan reads the crontab with `crontab -u <user> -l`. The step's `unlisted` holds each line it would remove: a job by its schedule and a hash of the line, never its command. The plan shows them going, and a warning names each job by its schedule and the first word of its command, which is enough to recognise it without printing an argument that might be a secret.

**What it doesn't touch.** `/etc/cron.d` and `/etc/crontab` are left alone, including the jobs that packages install there, and the jobs [`cron`](/modules/cron) steps write. So a `crontab` step says what's in the user's own crontab, not every job that runs as them.

**Root.** Reading or writing another user's crontab needs root: set `become = true` in the circuit's `ssh` block unless Conn3x logs in as root. The host needs the `crontab` command. On a minimal image without it, the step fails and says which package to install: `cron` on Debian and Ubuntu, `cronie` on Rocky, Fedora and RHEL.

**One step per user.** A circuit can't have two `crontab` steps for the same `user`, or a `crontab` step with `for_each`, since each would remove the other's jobs on every apply. That's checked when `user` is written out, such as `"deploy"`. Two steps whose `user` is computed, from a variable or `each.value`, aren't checked, so keep each user's jobs in one step.

**Changing it.** Changing the jobs or `env` updates the crontab in place. Changing `user` replaces the step.

## Removal

When you delete a `crontab` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the crontab as the step last wrote it. `"delete"` removes the user's whole crontab with `crontab -r`, so the jobs stop: set it when that's what you mean.

## From Ansible

Ansible's `cron` module has no way to own a whole crontab. `conn3x convert ansible` turns each `cron` task into a [`cron`](/modules/cron) step. A playbook whose `cron` tasks make up a user's whole crontab can become one `crontab` step by hand.
