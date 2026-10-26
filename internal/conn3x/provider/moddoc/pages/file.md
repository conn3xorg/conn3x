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
<!-- reference -->
## How it works

**Reading.** Every plan reads the file on the host: whether it exists, its mode, its owner and group, and its content. The plan shows a line-by-line diff of the content, so you review the exact change before it's made. With `content_wo`, state and the plan hold only `content_hmac`, and the diff shows that changing instead.

**Writing.** Conn3x writes the content to a temporary file in the same directory, sets its mode and ownership, flushes it to disk, and renames it over the old file. The directory is flushed afterwards too, so a power cut leaves the old file or the new one, never an empty one. On SELinux hosts the file is relabelled for its path with `restorecon`.

**Ownership.** `owner` and `group` are only checked and set when you give them. Leave them out and Conn3x keeps whatever the file has.

**Mode.** The default mode is `"0644"`, or `"0600"` for `content_wo`.

**Hand edits.** If someone edits the file on the host, the next plan shows the difference and `conn3x drift` reports it.

## Removal

When you delete a `file` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file where it is. `"delete"` removes it.

## From Ansible

`conn3x convert ansible` turns `copy` tasks with `content` or `src` into `file` steps, reading `src` from your playbook's `files/` directory. `copy` with `remote_src` stays a TODO.
