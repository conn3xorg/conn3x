Use `alternatives` to pick which program a generic name runs: which `java` a host has, which `python` or `editor`, which `x-www-browser`. That's `update-alternatives` on the Debian family and `alternatives` on the Red Hat family, and Conn3x runs whichever the host has.

## Example usage

Make `editor` open vim:

```hcl
step "editor" {
  alternatives {
    name = "editor"
    path = "/usr/bin/vim.basic"
  }
}
```

Register a program the host doesn't know yet, and point the name at it. `link` is where the generic command lives:

```hcl
step "java" {
  alternatives {
    name     = "java"
    link     = "/usr/bin/java"
    path     = "/opt/jdk-21/bin/java"
    priority = 2100
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `--display name` and reads what the name points to now and the priority of each registered path. `in_sync` is true when the name points to `path` and, with `priority` set, `path` is registered at that priority. A name the host doesn't know is out of sync, not an error.

**Applying.** When `path` isn't registered for `name`, or is registered at another priority, Conn3x runs `--install link name path priority`, with `priority` defaulting to 50. It then runs `--set name path` unless the name already points there. Setting a choice by hand puts the name in manual mode, so a package installed later with a higher priority doesn't take the name over.

**The link.** Registering needs the generic link. On the Debian family, `--display` prints it for a name the host knows, so `link` is only needed for a brand-new name. The Red Hat family's tool doesn't print it, so set `link` there whenever `path` has to be registered. Changing `link` for a registered name renames the link on Debian and fails on the Red Hat family; both are the tool's rules, not Conn3x's.

**The command.** Conn3x runs `update-alternatives` where it exists and `alternatives` otherwise. The Red Hat family's chkconfig ships both names, so the same step works on Rocky Linux, Fedora, Debian and Ubuntu.

**Changes.** Changing `path`, `link` or `priority` updates the choice in place. Changing `name` replaces the step, and the old name's choice is handled by its `on_remove`.

## Removal

`on_remove = "forget"`, the default, leaves the choice as it is. `on_remove = "delete"` runs `--remove name path`; the tool then picks the next best path, or drops the name when `path` was its last one. A path that isn't registered any more is left alone.

## From Ansible

`conn3x convert ansible` turns `community.general.alternatives` tasks with `state: selected`, the default, into `alternatives` steps, keeping `name`, `path`, `link` and `priority`. `state: present`, `auto` and `absent`, and `subcommands`, stay for review, since the step always selects `path` and has no slave links.
