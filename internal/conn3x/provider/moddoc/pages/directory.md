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

Hand a whole tree to an account, with directories it can list and files it can't run unless they already could be:

```hcl
step "app_release" {
  directory {
    path    = "/srv/app"
    owner   = "deploy"
    group   = "deploy"
    mode    = "u=rwX,g=rX,o="
    recurse = true
  }
}
```

Make sure an empty directory is gone, and stays gone:

```hcl
step "old_cache" {
  directory {
    path  = "/var/cache/app-legacy"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the directory on the host: whether it exists, its mode, and its owner and group. If something other than a directory is at the path, such as a file or a symbolic link, Conn3x stops with an error and doesn't replace it.

**Applying.** Conn3x runs `mkdir -p`, then sets the mode, owner and group. On SELinux hosts the directory is relabelled for its path with `restorecon`. Only the directory itself is changed, unless `recurse` is set. Missing parents are created by `mkdir -p` with mode 0755, whatever the login umask, and aren't managed; the directory's contents are left alone.

**Ownership.** `owner` and `group` are only checked and set when you give them. Leave them out and Conn3x keeps whatever the directory has.

**Mode.** The default mode is `"0755"`. If the mode on the host changes, the next plan shows the difference.

**Absent.** With `state = "absent"`, every plan checks only whether the directory exists. If it does, the plan shows the step out of sync and apply removes it. If it doesn't, the plan shows no change, and a directory that comes back later is removed again by the next apply. Only an empty directory is removed: one with anything in it is left in place, and the apply reports an error. `mode`, `owner` and `group` can't be set alongside it. A file, a symbolic link or anything else that isn't a directory at the path is an error, and is left in place.

A step working as root checks who can change the path first. If another user owns a directory on the way, the step runs as that user, so it can only do what they could, and `owner` can't be set to someone else there. A `group` that user isn't in is set by root afterwards, on the file itself. A directory of root's that one service account's group can write to, such as Debian's `/var/lib/bind`, counts as that account's: the step runs as the account, and root then sets the `owner` and `group` you gave. If several users could change the path, it stops with an error instead. [Paths as root](/guides/paths-as-root) lists the errors and what to do about each.

## Everything under it

With `recurse = true`, `owner`, `group` and `mode` go to everything under the directory as well as to the directory itself.

**Mode.** `mode` has to be symbolic, as `chmod` takes it, such as `"u=rwX,g=rX,o="`: each clause names `u`, `g`, `o` or `a`, then `=`, `+` or `-`, then any of `r`, `w`, `x` and `X`. `X` gives execute to directories, and to files that someone can already execute, so `"0755"` for directories doesn't make every file executable. That's why a numeric mode is refused with `recurse`. Setuid, setgid and sticky bits can't be given to a whole tree. Leave `mode` out to change only owner and group: the directory itself then gets `"0755"` as usual.

**The plan.** Every plan counts the paths under the directory whose owner, group or mode differ, without listing them. The step's `changes_under` holds the count, and the plan shows it going to 0. A warning says how many there are.

**What's left alone.**
- **Links:** a symbolic link's own owner and group change, but what it points to is never touched, and the walk never follows one.
- **Mounts:** a mount point under the directory, and everything on it, is left alone. Bind mounts count too, even from the same filesystem, since `/proc/self/mountinfo` lists every one.
- **Files with another hard link:** a file with more than one link that isn't already the new owner's is left as it is, since its other link could be anywhere, such as `/etc/shadow`. The warning counts them.

**Who does the walk.** Root does only what it must:
- **Owner:** only root can give files away. It does so with `chown -h`, from inside each directory, so a name swapped for a link on the way is never followed. That holds even in a directory others can write to, through its mode or an ACL: a link swapped in gets a new owner itself, and what it points to doesn't. Before that it checks `fs.protected_hardlinks`, and refuses if it's off. With it off, a user could hard-link a file of root's into the tree and have it handed to them.
- **Mode:** `chmod` always follows a link, so it runs as the user the tree then belongs to, and the kernel stops it at anything that isn't theirs. When that's root, `chmod` only runs in directories nobody else can change: root's, with no group or other write bit, and no ACL, since an ACL can let a user write there without showing in the mode. The step stops with an error naming any other directory.
- **Group:** without an `owner`, and with a `group` the owner is in, the whole walk runs as the owner, and root does nothing under the directory at all.

## Removal

When you delete a `directory` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the directory where it is. `"delete"` removes it only when it's empty. A directory with anything in it is left in place, and the apply reports an error.

## From Ansible

`conn3x convert ansible` turns `file` tasks with `state: directory` into `directory` steps, with `mode`, `owner` and `group`. `recurse: yes` carries over with a symbolic `mode`, such as `u=rwX,g=rX,o=`, or with only `owner` and `group`. A task that sets `recurse` with a numeric mode stays a TODO, since Ansible gives that mode to files and directories alike.
