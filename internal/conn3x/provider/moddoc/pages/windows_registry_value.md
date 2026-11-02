**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_registry_value` to set one value under `HKLM` on a Windows host. A value of type `expand_string` is compared as stored, with `%PATH%` left as `%PATH%`, so it doesn't show as changed on every plan.

## Example usage

```hcl
step "long_paths" {
  windows_registry_value {
    key  = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem"
    name = "LongPathsEnabled"
    type = "dword"
    data = "1"
  }
}
```

```hcl
step "app_dirs" {
  windows_registry_value {
    key  = "HKLM\\SOFTWARE\\MyApp"
    name = "Folders"
    type = "multi_string"
    data = "C:\\app\nC:\\data"
  }
}
```

A secret stays out of the plan and state:

```hcl
step "api_token" {
  windows_registry_value {
    key     = "HKLM\\SOFTWARE\\MyApp"
    name    = "Token"
    type    = "string"
    data_wo = "use an ephemeral variable here"
  }
}
```
<!-- reference -->
## How it works

**Data.** `dword` and `qword` take a decimal number, `binary` takes hex such as `0aff`, and `multi_string` takes one value per line.

**Secrets.** `data_wo` travels on stdin. A refresh asks the host for the SHA-256 of the value and compares a keyed hash with state, so drift still shows and the secret doesn't come back. Registry permissions decide who else can read it: `HKLM` values are readable by every user unless the key says otherwise, so a secret here needs a key you've locked down.

**Keys.** A missing key is created. Only `HKLM` is supported, in the 64-bit view.

## Removal

By default, deleting a `windows_registry_value` step leaves the value. With `on_remove = "delete"` it deletes the value and leaves the key.
