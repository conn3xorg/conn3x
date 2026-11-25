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

Put the sample config an installer left in place. `source_path` copies a file that's already on the host, and the next plan shows a change if either file changes:

```hcl
step "app_conf" {
  windows_file {
    path        = "C:\\app\\app.conf"
    source_path = "C:\\app\\app.conf.sample"
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

**Writing.** Conn3x makes a temp file beside the target with its access rules already on it, writes the content, then renames it over the target in one step. It does all of that, and a delete, through open handles: each folder is opened from the one above it, and the file from its folder, so no name is looked up a second time. A target that's already there with looser rules can't expose a new secret.

**Copying on the host.** With `source_path`, the content comes from a file on the same host, not from your configuration. Every plan hashes both files there with `Get-FileHash -Algorithm SHA256`, and only the hashes travel: `sha256` holds the copy's and `source_sha256` the source's, and the plan and state never hold either file's content. The step is in sync when the two match and the rules are what you set. A hand edit of the copy, or a new source, such as one an upgrade brought, shows as a change to `sha256`, and apply copies the source again. A source that's missing at plan shows as a copy too, since an earlier step in the same apply may create it. If it's still missing at apply, the step fails with `source_path C:\app\app.conf.sample doesn't exist on the host` and nothing is written. A source that's a folder, a link or a junction, or has one on the way, is an error at plan and at apply: Conn3x opens the source the way it opens the target, from its folder, and holds it so nothing can write to it during the copy. The copy takes the target's rules as `content` does, never the source's. There's no 2 MiB limit, since the content never leaves the host.

**What state keeps.** `content_hmac` is a keyed HMAC over the path and the content's hash, which is what lets a refresh compare it with the hash the host reports. Unlike a `password_hmac` it isn't stretched or tied to the host, so keep the HMAC key away from the state: someone holding both could test guesses at a short secret.

**Links.** It never writes through a symbolic link, a junction or a mount point, at the path or on the way to it, and it refuses a file with other hard links. Use the real path.

**Folders others can change.** While it writes, every folder on the way is held open, so none can be renamed or removed. With `content_wo` or `acl` it also refuses a folder that belongs to, or lets delete from, rename or re-permission, anyone but SYSTEM, Administrators, TrustedInstaller or the login itself, since that account could replace the file afterwards. The right to add new entries is fine. On a stock Azure image, every signed-in user can modify a new folder under `C:\`, so give that folder its own rules with [`windows_directory`](windows_directory.md)'s `acl` before putting a secret below it.

**The folder must already exist.** Make it with [`windows_directory`](windows_directory.md) first.

**Rules on an existing file.** With no `acl` and no `content_wo`, a rewrite keeps the rules already on the file, unless another account owns it. Use `acl`, or [`windows_acl`](windows_acl.md) for a few added rules, but not both on one path.

**Secrets.** `content_wo` travels on stdin. Refresh compares a keyed hash of the file's SHA-256 with state, so drift still shows and the content never leaves the host again. Errors have the value blanked.

**Size.** `content` and `content_wo` are limited to 2 MiB.

## Removal

By default, deleting a `windows_file` step leaves the file. With `on_remove = "delete"` it deletes the file, or a link standing in its place, but never what a link points to.

## From Ansible

`conn3x convert ansible` turns `win_copy` tasks with `content` into `windows_file` steps, and reads `src` from your playbook's `files/` directory. With `remote_src: true`, a `src` that's a full path on a local drive, such as `C:\app\app.conf.sample`, becomes `source_path`. A `src` ending in `\` or `/` copies a folder recursively, which a `windows_file` step can't, so it stays a TODO, and so does any other `src` with `remote_src`. `force: no` stays a TODO too, since Ansible then writes the file only when it's missing.
