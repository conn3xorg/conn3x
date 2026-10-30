Use `directory` to make sure a directory exists on a host, with its mode and optionally its owner and group. Conn3x creates any missing parent directories too.

## Example usage

Create a directory:

```hcl
step "app_dir" {
  directory {
    path = "/opt/app"
  }
}
```

Set the owner, group and mode:

```hcl
step "app_data" {
  directory {
    path  = "/var/lib/app"
    owner = "app"
    group = "app"
    mode  = "0750"
  }
}
```

Create several directories, one instance per directory and host:

```hcl
step "app_tree" {
  for_each = ["/srv/app/releases", "/srv/app/shared", "/srv/app/logs"]
  directory {
    path = item.value
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the directory on the host: whether it exists, its mode, and its owner and group. If something other than a directory is at the path, such as a file or a symbolic link, Conn3x stops with an error and doesn't replace it.

**Applying.** Conn3x runs `mkdir -p`, then sets the mode, owner and group. On SELinux hosts the directory is relabelled for its path with `restorecon`. Only the directory itself is changed. Missing parents are created by `mkdir -p` and aren't managed, and the directory's contents are left alone.

**Ownership.** `owner` and `group` are only checked and set when you give them. Leave them out and Conn3x keeps whatever the directory has.

**Mode.** The default mode is `"0755"`. If the mode on the host changes, the next plan shows the difference.

A `directory` step acts as root on the path you name, and follows a symlink at that path. Don't manage a root-owned path inside a directory a non-root user can write to, because that user can swap what the path points to.

## Removal

When you delete a `directory` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the directory where it is. `"delete"` removes it only when it's empty. A directory with anything in it is left in place, and the apply reports an error.

## From Ansible

`conn3x convert ansible` turns `file` tasks with `state: directory` into `directory` steps, with `mode`, `owner` and `group`. A task that sets `recurse` stays a TODO.
