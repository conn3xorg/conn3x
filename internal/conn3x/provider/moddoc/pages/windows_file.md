**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_file` to put a file on a Windows host, byte for byte. Line endings stay as you wrote them, and the file appears all at once, so nothing ever reads half of it.

## Example usage

```hcl
step "config" {
  windows_file {
    path    = "C:\\app\\config.json"
    content = jsonencode({ port = 8080 })
  }
}
```

A secret stays out of the plan and state. Only SYSTEM and Administrators can read the file, from the moment it exists:

```hcl
step "api_key" {
  windows_file {
    path       = "C:\\app\\api.key"
    content_wo = "use an ephemeral variable here"
  }
}
```

Name who gets access yourself:

```hcl
step "readable_by_the_app" {
  windows_file {
    path    = "C:\\app\\settings.ini"
    content = "mode = production\n"

    acl {
      principal = "S-1-5-32-544"
      rights    = ["FullControl"]
    }
    acl {
      principal = "S-1-5-18"
      rights    = ["FullControl"]
    }
    acl {
      principal = "NT SERVICE\\MyApp"
      rights    = ["Read"]
    }
  }
}
```
<!-- reference -->
## How it works

**Writing.** Conn3x makes a temp file beside the target with its access rules already on it, writes the content, then renames it over the target in one step. A target that's already there with looser rules can't expose a new secret.

**Links.** It never writes through a symbolic link, a junction or a mount point, at the path or on the way to it, and it refuses a file with other hard links. Use the real path.

**Folders others can change.** While it writes, every folder on the way is held open, so none can be renamed or removed. With `content_wo` or `acl` it also refuses a folder that belongs to, or lets delete from, rename or re-permission, anyone but SYSTEM, Administrators, TrustedInstaller or the login itself, since that account could replace the file afterwards. The right to add new entries is fine. On a stock Azure image, every signed-in user can modify a new folder under `C:\`, so give that folder its own rules with [`windows_directory`](windows_directory.md)'s `acl` before putting a secret below it.

**The folder must already exist.** Make it with [`windows_directory`](windows_directory.md) first.

**Rules on an existing file.** With no `acl` and no `content_wo`, a rewrite keeps the rules already on the file, unless another account owns it. Use `acl`, or [`windows_acl`](windows_acl.md) for a few added rules, but not both on one path.

**Secrets.** `content_wo` travels on stdin. Refresh compares a keyed hash of the file's SHA-256 with state, so drift still shows and the content never leaves the host again. Errors have the value blanked.

**Size.** Content is limited to 2 MiB.

## Removal

By default, deleting a `windows_file` step leaves the file. With `on_remove = "delete"` it deletes the file, or a link standing in its place, but never what a link points to.
