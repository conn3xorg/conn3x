Use `limit` to set one PAM limit, such as how many files a service account can open, by keeping one line in a `limits.conf` file. Other lines stay as they are, so several steps can share a file.

## Example usage

Let `app` open more files:

```hcl
step "app_files" {
  limit {
    path   = "/etc/security/limits.d/90-app.conf"
    domain = "app"
    type   = "soft"
    item   = "nofile"
    value  = "64000"
    create = true
  }
}
```

Let a group dump core, with both the soft and hard limit:

```hcl
step "ops_core" {
  limit {
    path   = "/etc/security/limits.conf"
    domain = "@ops"
    type   = "-"
    item   = "core"
    value  = "unlimited"
  }
}
```

Take a limit out again:

```hcl
step "no_app_procs" {
  limit {
    path   = "/etc/security/limits.conf"
    domain = "app"
    type   = "hard"
    item   = "nproc"
    state  = "absent"
  }
}
```
<!-- reference -->
## How it works

**Finding the line.** A line belongs to the limit when its domain, type and item match exactly. Spacing doesn't count, and neither do comments, so `#app soft nofile 1` isn't a match. `@ops` and `ops` are different domains, and domains are case sensitive.

**Setting a value.** If a matching line already has the value, it isn't touched. Otherwise the first matching line takes the value, keeping any comment after it, and any further matching lines go, since PAM uses the last one it reads. A new limit goes at the end of the file, written with tabs.

**Values.** `value` is a number, or `-1`, `"unlimited"` or `"infinity"` for no limit. `nice` and `priority` take `-20` to `19`. Conn3x checks these before connecting to the host, along with `type` and `item`.

**When it takes effect.** PAM reads limits at login, so a running service or an open session keeps its old limits. And `systemd` services don't read this file at all: set `LimitNOFILE` and friends in the unit for those.

**Writing.** Conn3x writes the edited content the same way as [`file`](/modules/file): to a temporary file in the same directory, renamed over the old one, and relabelled with `restorecon` on SELinux hosts. If `path` is a symlink, the file it points to is written and the link stays. The file keeps its mode, owner and group. Steps that edit the same file take turns.

**Missing files.** A missing file is an error, unless you set `create = true` or `state = "absent"`. A file created this way has mode `"0644"`, along with any missing parent directories.

**Conflicts.** If another step in the same circuit writes the whole file with `file` or `template`, `conn3x validate` warns you, because each apply would undo the other.

## Removal

When you delete a `limit` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file as it is. `"delete"` removes the limit.

## From Ansible

`conn3x convert ansible` turns `community.general.pam_limits` tasks into `limit` steps. `dest` becomes `path`, with Ansible's default of `/etc/security/limits.conf` spelled out, and the converter adds `create = true`, because `pam_limits` creates a missing file.

A task stays a TODO with the reason when it sets `use_min`, `use_max`, `backup` or `comment`, or an argument `limit` doesn't have. So does a task written as `key=value` text, one with a loop, and one with a value YAML could read as something else, such as `010` or `1.5`.

Three things differ and can't be seen from the playbook, though PAM ends up with the same limit in each. The converted step writes through a symlink at `path`, where `pam_limits` replaces the link with a file. It keeps one line for a limit, where `pam_limits` updates every copy and leaves them. It creates missing parent directories, where `pam_limits` fails.
