Use `line` to make sure one line is in a text file, or isn't, without managing the rest of the file. To manage several lines together, use [`block`](/modules/block). To manage the whole file, use [`file`](/modules/file).

## Example usage

Replace a setting, or add it when no line matches:

```hcl
step "no_root_login" {
  line {
    path   = "/etc/ssh/sshd_config"
    regexp = "^#?PermitRootLogin"
    line   = "PermitRootLogin no"
  }
}
```

Add a line after a section header, creating the file if it's missing:

```hcl
step "swappiness" {
  line {
    path         = "/etc/sysctl.d/90-app.conf"
    line         = "vm.swappiness = 10"
    insert_after = "^# memory"
    create       = true
  }
}
```

Remove every line that matches:

```hcl
step "no_legacy_mirror" {
  line {
    path   = "/etc/hosts"
    regexp = "mirror\\.legacy\\.example\\.com"
    state  = "absent"
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the file on the host and applies the edit to a copy of its content. If the result is the same as the file, the step is in sync and nothing is planned. Otherwise the plan shows an update.

**Matching.** With `regexp`, Conn3x replaces the last line that matches. When no line matches, and the exact `line` isn't already in the file, it adds `line` at the place `insert_after` or `insert_before` gives. Without `regexp`, it adds `line` only when no line is exactly equal to it. `insert_after` uses the last matching line and `insert_before` the first. When neither matches, or you set neither, the line goes at the end of the file. `"BOF"` and `"EOF"` stand for the start and the end.

**Removing lines.** With `state = "absent"`, Conn3x removes every line equal to `line`, or every line matching `regexp` when you set one.

**Writing.** Conn3x writes the edited content the same way as [`file`](/modules/file): to a temporary file in the same directory, renamed over the old one, and relabelled with `restorecon` on SELinux hosts. The file keeps its mode, owner and group. When nothing changes, the file isn't written.

**Missing files.** A missing file is an error, unless you set `create = true`. A file created this way has mode `"0644"`.

**Conflicts.** If another step in the same circuit writes the whole file with `file` or `template`, `conn3x validate` warns you, because each apply would undo the other. Put the line into that file's content instead.

## Checking the file first

For a file a mistake could lock you out of, such as `sshd_config` or `sudoers`, set `validate` to a command that checks the edited file. Conn3x writes the edit to a temporary file, runs the command with `%s` as its path, and swaps the file in only if the command exits 0. Otherwise the file is left as it was, and the step fails with the command's output:

```hcl
line {
  path     = "/etc/ssh/sshd_config"
  regexp   = "^PermitRootLogin"
  line     = "PermitRootLogin no"
  validate = "/usr/sbin/sshd -t -f %s"
}
```

It runs only when the edit changes the file, and isn't kept in state. Removing the step with `on_remove = "delete"` doesn't run it, since the step's configuration is gone by then.

## Removal

When you delete a `line` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file as it is. `"delete"` removes lines equal to `line`. It doesn't restore a line that `regexp` replaced.

## From Ansible

`conn3x convert ansible` turns `lineinfile` tasks into `line` steps, with `insertafter`, `insertbefore`, `create`, `state` and `validate` carried across. A task that uses `backrefs` stays a TODO.
