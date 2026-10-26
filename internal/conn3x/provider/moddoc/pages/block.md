Use `block` to manage several lines in a text file as one unit, between a pair of marker lines, and leave the rest of the file alone. For a single line, use [`line`](/modules/line). To manage the whole file, use [`file`](/modules/file).

## Example usage

Add a block of host entries:

```hcl
step "internal_hosts" {
  block {
    path    = "/etc/hosts"
    content = <<-EOT
      10.0.0.10 db1.internal
      10.0.0.11 db2.internal
    EOT
  }
}
```

Place a block before a line, with your own markers:

```hcl
step "sshd_match" {
  block {
    path          = "/etc/ssh/sshd_config"
    marker        = "# {mark} deploy user"
    insert_before = "^Match "
    content       = <<-EOT
      Match User deploy
        PasswordAuthentication no
    EOT
  }
}
```

Remove a block that an earlier configuration added:

```hcl
step "old_hosts" {
  block {
    path  = "/etc/hosts"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**Markers.** Conn3x finds the block by its marker lines: `marker` with `{mark}` replaced by `BEGIN` and `END`. The default marker gives `# BEGIN CONN3X MANAGED BLOCK` and `# END CONN3X MANAGED BLOCK`. Each step in the same file needs its own marker. If the file has a `BEGIN` line with no matching `END`, Conn3x stops with an error, so you can fix the file by hand.

**Reading.** Every plan reads the file on the host and applies the edit to a copy of its content. If the result is the same as the file, the step is in sync and nothing is planned. Otherwise the plan shows an update.

**Applying.** When the markers are in the file, Conn3x replaces everything between them with `content`. When they aren't, it adds the markers and the content at the place `insert_after` or `insert_before` gives, or at the end of the file. `insert_after` uses the last matching line and `insert_before` the first. `"BOF"` and `"EOF"` stand for the start and the end. With `state = "absent"`, Conn3x removes the block and its markers.

**Writing.** Conn3x writes the edited content the same way as [`file`](/modules/file): to a temporary file in the same directory, renamed over the old one, and relabelled with `restorecon` on SELinux hosts. The file keeps its mode, owner and group. When nothing changes, the file isn't written.

**Missing files.** A missing file is an error, unless you set `create = true`. A file created this way has mode `"0644"`.

**Conflicts.** If another step in the same circuit writes the whole file with `file` or `template`, `conn3x validate` warns you, because each apply would undo the other.

## Removal

When you delete a `block` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file as it is. `"delete"` removes the block and its markers.

## From Ansible

`conn3x convert ansible` turns `blockinfile` tasks into `block` steps. It keeps Ansible's marker, `# {mark} ANSIBLE MANAGED BLOCK` by default, so the block Ansible already wrote is the one Conn3x manages. A task that sets `marker_begin` or `marker_end` stays a TODO.
