**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_acl` for access rules on a file or folder that already exists on a Windows host. By default it only adds what's listed. Rules are compared by SID, so a name in another case or another display language never shows as a change.

## Example usage

Add a rule:

```hcl
step "uploads" {
  windows_acl {
    path = "C:\\app\\uploads"

    entry {
      principal = "BUILTIN\\IIS_IUSRS"
      rights    = ["Modify"]
    }
  }
}
```

Make the list the whole truth, with nothing inherited:

```hcl
step "lock_down" {
  windows_acl {
    path          = "C:\\app\\private"
    authoritative = true
    inherit       = false
    owner         = "S-1-5-32-544"

    entry {
      principal = "S-1-5-32-544"
      rights    = ["FullControl"]
    }
    entry {
      principal = "S-1-5-18"
      rights    = ["FullControl"]
    }
    entry {
      principal = "S-1-1-0"
      rights    = ["Write"]
      type      = "deny"
    }
  }
}
```
<!-- reference -->
## How it works

**Links.** It won't change rules through a symbolic link, junction or mount point, at the path or on the way to it, and refuses a file with other hard links, since rules belong to the file and not the name. Rules on a folder reach what's inside it, but stop at a link inside it.

**Folders others can change.** It holds every folder on the way open while it works, and refuses one that another account could change. See [`windows_file`](windows_file.md) for exactly what counts.

**Inherited rules.** `authoritative` removes rules set directly on the path. Rules it inherits stay until `inherit = false`.

**A missing principal** is an error at apply. A refresh shows it as a difference.

## Removal

Deleting a `windows_acl` step leaves the rules as they are.
