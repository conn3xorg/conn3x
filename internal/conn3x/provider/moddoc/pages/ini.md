Use `ini` to set or remove one option in an INI-style file without managing the rest of it. Comments, other options and other sections stay where they are. To replace text that isn't an option, use [`replace`](/modules/replace) or [`line`](/modules/line). To manage the whole file, use [`file`](/modules/file).

## Example usage

Set an option in a section, adding the section if it's missing:

```hcl
step "php_memory" {
  ini {
    path    = "/etc/php.ini"
    section = "PHP"
    option  = "memory_limit"
    value   = "512M"
  }
}
```

Set an option in a file with no sections, with no spaces around the `=`, creating the file if it's missing:

```hcl
step "app_port" {
  ini {
    path            = "/etc/app.env"
    option          = "PORT"
    value           = "8080"
    no_extra_spaces = true
    create          = true
  }
}
```

Remove an option:

```hcl
step "no_legacy_tls" {
  ini {
    path    = "/etc/app.conf"
    section = "tls"
    option  = "allow_tls10"
    state   = "absent"
  }
}
```

Turn an example the file ships with into a real setting:

```hcl
step "workers" {
  ini {
    path      = "/etc/app.conf"
    section   = "server"
    option    = "workers"
    value     = "8"
    uncomment = true
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the file on the host and applies the edit to a copy of its content. If the result is the same as the file, the step is in sync and nothing is planned. Otherwise the plan shows an update, and `conn3x drift` reports it.

**Finding the option.** A section starts at a line beginning `[name]` and runs to the next line beginning with `[` that has a `]`. Without `section`, Conn3x looks before the first section. If several sections have the same name, only the first is used. An option is matched by its exact name, before the `=`, with any spaces around it ignored. A line holding only the name also counts. Lines that use `:` as the separator don't.

**Setting a value.** The first line for the option becomes `option = value`, or `option=value` with `no_extra_spaces`, and any further lines for it go. The whole line is rewritten, so indentation goes, and so does anything after the value, including a comment on the same line. A new option goes after the last setting in its section, and a new section goes at the end of the file.

**Comments.** Comment lines are left alone. With `uncomment = true`, a line that starts with one `#` or `;` and sets this option counts as a line for the option, so the first such line takes the value and any others go. Comments that don't set the option stay either way.

**Removing an option.** With `state = "absent"`, every line for the option in that section goes. Comments and the section header stay. A missing file already meets this, so nothing is created and nothing fails.

**Writing.** Conn3x writes the edited content the same way as [`file`](/modules/file): to a temporary file in the same directory, renamed over the old one, and relabelled with `restorecon` on SELinux hosts. If `path` is a symlink, the file it points to is written and the link stays. The file keeps its mode, owner and group. When nothing changes, the file isn't written. Steps that edit the same file take turns.

**Line endings.** The file always ends with a newline afterwards, so a file without one shows an update the first time. A file whose first line ends in CRLF keeps CRLF, and new lines get it too. A byte order mark is dropped when the file changes.

**Missing files.** A missing file is an error, unless you set `create = true` or `state = "absent"`. A file created this way has mode `"0644"`, along with any missing parent directories.

**Secrets.** `value` is stored in state and shown in plans, like the text of a [`line`](/modules/line) step. Don't put a secret in it; write a file holding secrets with [`file`](/modules/file) and its write-only content.

**Conflicts.** If another step in the same circuit writes the whole file with `file` or `template`, `conn3x validate` warns you, because each apply would undo the other.

## Removal

When you delete an `ini` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file as it is. `"delete"` removes the option. It doesn't bring back a value the step replaced.

## From Ansible

`conn3x convert ansible` turns `community.general.ini_file` tasks that set or remove one option into `ini` steps. Two defaults differ, so the converter spells them out: `create = true`, because `ini_file` creates missing files, and `uncomment = true`, because it takes over commented-out lines unless you set `modify_inactive_option: no`.

A task stays a TODO with the reason when it changes a whole section, or sets `exclusive: no`, `values`, `section_has_values`, `allow_no_value`, `ignore_spaces`, `backup`, `mode`, `owner`, `group` or any other argument `ini` doesn't have. So does a task written as `key=value` text, one with a loop, and one with an unquoted value that YAML could read as something else, such as `yes`, `1.10` or `0644`. Quote those and convert again.

Three things differ and can't be seen from the playbook, so check them on hosts where they apply. The converted step writes through a symlink at `path`, where `ini_file` without `follow` replaces the link with a file. It keeps CRLF line endings, where `ini_file` rewrites them. A file it creates has mode `"0644"` whatever the host's umask.
