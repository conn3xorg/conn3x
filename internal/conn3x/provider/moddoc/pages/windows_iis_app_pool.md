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

**Identity.** Every site in a pool runs as its identity. `LocalSystem` has full rights over the host, and `ApplicationPoolIdentity`, `NetworkService` and `LocalService` can impersonate their way to SYSTEM, so a folder anyone else can write to is a way in, whichever you pick. `windows_iis_site` refuses such a folder. When this step changes an existing pool's identity, it checks the folders of every site and application already in the pool the same way, including ones Conn3x doesn't manage, and refuses the change if any of them isn't admin-only. A pool running as a named account with a password isn't supported yet.

## Removal

By default, deleting a `windows_iis_app_pool` step deletes the pool. With `on_remove = "forget"` the pool stays. A site still using a deleted pool won't serve until it gets another.
