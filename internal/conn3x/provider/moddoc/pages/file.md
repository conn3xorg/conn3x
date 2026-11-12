Use `file` to manage a regular file on a host: its exact content, its mode, and optionally its owner and group. To build the content from a template on your machine, use [`template`](/modules/template), which becomes a `file` step.

## Example usage

Write a file:

```hcl
step "motd" {
  file {
    path    = "/etc/motd"
    content = "Hello from ${each.key}, managed by Conn3x.\n"
  }
}
```

Copy a file from beside your configuration, with an owner and a mode:

```hcl
step "app_config" {
  file {
    path    = "/etc/app/app.conf"
    content = "listen = 8080\n"
    mode    = "0640"
    owner   = "root"
    group   = "app"
  }
}
```

Keep a secret out of the plan and state with `content_wo`, passed in at run time:

```hcl
step "db_password" {
  file {
    path       = "/etc/app/db-password"
    content_wo = "use an ephemeral variable here"
  }
}
```

In a real configuration, set `content_wo` from a variable with `ephemeral = true`, as [Secrets in files](/concepts#secrets-in-files) shows. To read the content from a file next to your configuration, use `content = file("${path.module}/files/app.conf")`.

Check a sudoers drop-in with `visudo` before it goes live, so a typo can't lock you out of `sudo`:

```hcl
step "sudoers" {
  file {
    path     = "/etc/sudoers.d/deploy"
    content  = "deploy ALL=(ALL) NOPASSWD: ALL\n"
    mode     = "0440"
    validate = "visudo -cf %s"
  }
}
```

Change sshd's settings under a guard, so a mistake that locks Conn3x out puts itself back:

```hcl
step "sshd" {
  file {
    path          = "/etc/ssh/sshd_config.d/99-hardening.conf"
    content       = "PasswordAuthentication no\n"
    reload        = "systemctl reload sshd"
    confirm_after = "60s"
  }
}
```

Make sure a file is gone, and stays gone:

```hcl
step "old_config" {
  file {
    path  = "/etc/app/legacy.conf"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the file on the host: whether it exists, its mode, its owner and group, and its content. The plan shows a line-by-line diff of the content, so you review the exact change before it's made. With `content_wo`, state and the plan hold only `content_hmac`, and the diff shows that changing instead.

The login user has to be able to read the file. If it can't, the plan stops with an error that names the user, such as `/etc/app.conf exists but can't be read by deploy`. Set `become = true` in the circuit's [`ssh` block](/reference/circuits/ssh#become) so Conn3x reads it through `sudo`, or give the file a mode the login user can read.

**Writing.** If the parent directory doesn't exist, Conn3x creates it first. Conn3x writes the content to a temporary file in the same directory, sets its mode and ownership, flushes it to disk, and renames it over the old file. The directory is flushed afterwards too, so a power cut leaves the old file or the new one, never an empty one. On SELinux hosts the file is relabelled for its path with `restorecon`.

**Validating.** With `validate`, Conn3x runs the command on the temporary file once it has its final mode and owner, with `%s` replaced by the temporary file's path. The path is already quoted, so write `%s` bare, not `'%s'`. If the command exits 0, the file is moved into place. If it doesn't, the original file is left untouched, the temporary file is removed, and apply fails with the command's output. With `content_wo` the output is hidden, since the command may print the secret it was checking. `validate` runs only when the content is changing, not when only the mode or ownership is. It's write-only, so adding it to an existing step doesn't show a change in the plan.

**Confirming.** For a change that could lock Conn3x out, such as sshd's settings, set `confirm_after`. Before writing, the host copies the old file, or notes that there was none, into `/var/lib/conn3x/revert`, which only root can read. It then schedules its own revert with `systemd-run`, due that long after. The revert is a timer in the host's own systemd, so it runs even if Conn3x goes away mid-apply: if your laptop dies or the network drops, the host still puts itself back. Conn3x writes the file, runs `reload`, and logs in again over a new connection with the circuit's whole `ssh` block, jump hosts and host key check included. Once that login works, it cancels the revert and removes the copy. If the write or the reload fails, Conn3x reverts at once. If the new login doesn't come in time, the host puts the old file back and runs `reload` again by itself. Conn3x waits for that, checks whether the host answers again, and fails the step saying which happened. The guard is armed whenever the file changes: its content, mode or ownership, since a mode sshd's `StrictModes` refuses locks you out as surely as bad content. A link at `path` is put back as the link it was, since writing replaces the link rather than what it points to. `confirm_after` is between `10s` and `1h`, needs systemd on the host, and can't be set with `state = "absent"`. The copy and the revert are root's work, so the step refuses `confirm_after` for a file that another user could lead somewhere else: one below a directory another user owns, such as a home directory, or directly in one anyone can create files in, such as `/tmp`. `reload` goes with it. A handler the step notifies runs after the confirm. A `template` step takes both arguments too.

**Ownership.** `owner` and `group` are only checked and set when you give them. Leave them out and Conn3x keeps whatever the file has. The exception is a directory anyone can create files in, such as `/tmp`: if another user's file is already at `path` there, a step working as root stops instead of handing the new content to that user. Set `owner` and `group`, or remove the file first.

**Mode.** The default mode is `"0644"`, or `"0600"` for `content_wo`.

**Absent.** With `state = "absent"`, every plan checks only whether the file exists, without reading it. If it does, the plan shows the step out of sync and apply removes it. If it doesn't, the plan shows no change, and a file that comes back later is removed again by the next apply. `content`, `content_wo`, `mode`, `owner` and `group` can't be set alongside it. A directory or anything else that isn't a regular file at the path is an error, and is left in place.

**Hand edits.** If someone edits the file on the host, the next plan shows the difference and `conn3x drift` reports it.

A step working as root checks who can change the path first. If another user owns a directory on the way, the step runs as that user, so it can only do what they could, and `owner` can't be set to someone else there. A `group` that user isn't in is set by root afterwards, on the file itself. A directory of root's that one service account's group can write to, such as Debian's `/var/lib/bind`, counts as that account's: the step runs as the account, and root then sets the `owner` and `group` you gave. If several users could change the path, it stops with an error instead. [Paths as root](/guides/paths-as-root) lists the errors and what to do about each.

## Removal

When you delete a `file` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file where it is. `"delete"` removes it.

## From Ansible

`conn3x convert ansible` turns `copy` tasks with `content` or `src` into `file` steps, reading `src` from your playbook's `files/` directory. `copy` with `remote_src` stays a TODO, and so does `force: no`, since Ansible then writes the file only when it's missing. A task without `mode` gets a TODO note on its step: Ansible leaves the mode of a file that's already there, and a `file` step sets `0644`, so set `mode` where the file should stay tighter. A `validate` carries over, minus any quotes around `%s`. Ansible runs it without a shell, so a `validate` with pipes, redirects, `$`, globs, a second line or other shell syntax stays a TODO, because Conn3x would run those through `sh`.

`file` tasks with `state: absent` become `file` steps with `state = "absent"`. Ansible removes whatever is at the path, even a directory and everything in it, while a `file` step removes a file and stops with an error at anything else, so the step carries a note saying so. If the path holds a directory or a link, change the step to [`directory`](/modules/directory) or [`link`](/modules/link). Other arguments alongside `state: absent` send the task to review.

A play that sets `become_user`, or `remote_user` without `become`, or that has `ansible.cfg`, `group_vars`, `host_vars` or a `vars_files` file beside it setting who its tasks run as, sends these tasks to review with the reason, because who runs them decides who owns what they create. A circuit runs as root under `become` and otherwise as its login user.
