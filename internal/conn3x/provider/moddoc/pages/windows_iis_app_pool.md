**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_iis_app_pool` to create an IIS application pool and keep it started or stopped. IIS must be installed first, which a `windows_feature` step for `Web-Server` does.

## Example usage

```hcl
step "iis" {
  windows_feature {
    name = "Web-Server"
  }
}

step "app_pool" {
  windows_iis_app_pool {
    name                    = "shop"
    managed_runtime_version = ""
  }
}
```
<!-- reference -->
## How it works

Every setting you leave out takes IIS's own default for a new pool, so a pool changed by hand shows as drift: runtime `v4.0`, `integrated` pipeline, `ApplicationPoolIdentity`, started. `state` also sets whether the pool starts with IIS, so a stopped pool stays stopped after a reboot.

Conn3x reads pools through `Microsoft.Web.Administration`, opened read-only, and never through the `IIS:` drive. On a host without IIS, a pool reads as missing rather than failing, so a plan made before the `windows_feature` step runs still works.

**Identity.** `LocalSystem` runs every site in the pool with full rights over the host, and `NetworkService` and `LocalService` share an account with other services. Anyone who can change a site's files can then run code as that account. Keep `ApplicationPoolIdentity` unless the application needs another, and keep the site's folder writable by administrators only. A pool running as a named account with a password isn't supported yet.

## Removal

By default, deleting a `windows_iis_app_pool` step deletes the pool. With `on_remove = "forget"` the pool stays. A site still using a deleted pool won't serve until it gets another.
