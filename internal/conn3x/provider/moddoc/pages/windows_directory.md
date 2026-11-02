**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_directory` to make a folder, and any missing above it, on a Windows host. With `acl` the folder has its rules from the moment it exists, so there's no moment when anyone else can get in.

## Example usage

```hcl
step "app" {
  windows_directory {
    path = "C:\\app"
  }
}
```

```hcl
step "private" {
  windows_directory {
    path = "C:\\app\\private"

    acl {
      principal = "S-1-5-32-544"
      rights    = ["FullControl"]
    }
    acl {
      principal = "S-1-5-18"
      rights    = ["FullControl"]
    }
  }
}
```
<!-- reference -->
## How it works

It holds each folder on the way open, so none can be renamed or removed while it works, and it won't pass through a symbolic link, junction or mount point. With `acl`, it also refuses a folder on the way that another account could change, and the folder itself if another account owns it. See [`windows_file`](windows_file.md) for exactly what counts.

## Removal

Deleting a `windows_directory` step leaves the folder and everything in it.
