Use `acl` to give one more user or group access to a file or directory without changing its owner, group or mode: a backup user that reads `/srv/data`, a deploy group that writes to a web root. It keeps one POSIX ACL entry and leaves the others as they are, with `getfacl` and `setfacl`. It's `ansible.posix.acl`.

## Example usage

The host needs the `acl` package, which minimal images often leave out:

```hcl
step "acl_tools" {
  package {
    name = "acl"
  }
}
```

Let the `backup` user read a directory:

```hcl
step "backup_reads" {
  depends_on = [conn3x_package.files__acl_tools]

  acl {
    path        = "/srv/data"
    etype       = "user"
    entity      = "backup"
    permissions = "rx"
  }
}
```

And files made in it later, through its default ACL:

```hcl
step "backup_reads_new_files" {
  acl {
    path        = "/srv/data"
    etype       = "user"
    entity      = "backup"
    permissions = "r"
    default     = true
  }
}
```

Take an entry out:

```hcl
step "no_more_contractors" {
  acl {
    path   = "/srv/data"
    etype  = "group"
    entity = "contractors"
    state  = "absent"
  }
}
```
<!-- reference -->
## How it works

**One entry.** Each step owns one entry: `etype` and `entity`, on the path's own ACL or, with `default = true`, a directory's default ACL. Two steps can own two entries on one path. Conn3x reads them with `getfacl --omit-header --absolute-names --no-effective` and writes with `setfacl -m`, or `setfacl -x` for `state = "absent"`. Apply changes nothing when the entry is already right. `permissions` is any of `r`, `w` and `x` in any order, and `""` is an entry with none, which still takes away what the group or other entries would give that user.

**The mask.** `setfacl` raises the path's mask so the entry can have what it asks for, and the mask is what the group digit of the mode shows once a path has an ACL. So an entry with `w` on a directory a `directory` step keeps at `0750` makes the two disagree, and each plan puts one back. Give the mode the group digit the entries need, such as `0770`, or keep the mask yourself with an `etype = "mask"` step.

**Reading.** Every plan reads the ACL again. An entry changed or removed by hand shows the step out of sync, and the next apply puts it back.

**What it refuses.** A relative path, a user or group entry without `entity`, a mask or other entry with one, and `state = "absent"` on a path's own mask or other entry, which every path has. The owner's and the owning group's own entries are the mode: set those with a `file` or `directory` step. Without `setfacl` on the host, the step fails and says to install the `acl` package.

## Removal

Deleting an `acl` step leaves the entry. With `on_remove = "delete"`, a user or group entry is taken out.
