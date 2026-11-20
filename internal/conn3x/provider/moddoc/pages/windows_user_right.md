Use `windows_user_right` to make sure the right accounts hold a user right on a Windows host, such as logging on as a service. Principals are compared by SID, so `.\svc_app` and `WEB01\svc_app` are the same account.

## Example usage

```hcl
step "svc_app_logon" {
  windows_user_right {
    name       = "SeServiceLogonRight"
    principals = [".\\svc_app"]
  }
}
```

```hcl
step "no_debug" {
  windows_user_right {
    name          = "SeDebugPrivilege"
    principals    = ["Administrators"]
    authoritative = true
  }
}
```
<!-- reference -->
## How it works

**Principals.** By default, `principals` are granted the right and nobody else loses it. With `authoritative = true` the list is complete: anyone else loses the right on apply, and an empty list clears it.

**Lockout.** Conn3x refuses to leave the login it uses without a logon right it holds, such as `SeNetworkLogonRight`, through its own SID or any group it's in. It also refuses to give that login a deny-logon right, such as `SeDenyNetworkLogonRight`. So narrowing "Access this computer from the network" to `Administrators` is fine while the login is an administrator, and apply fails if it would take the right from the login altogether.

A principal that doesn't exist yet, such as a user a later step makes, shows the right as out of sync rather than failing the plan. At apply, a name that still doesn't resolve is an error, and so is a right Windows doesn't have.

**Group Policy.** A Group Policy that sets a right, from the domain or the local policy, puts it back at its next refresh, so the step shows as out of sync again. Set the right in that policy instead.

**Reading.** No PowerShell command reads a user right, so the plan compiles a small type that asks the Local Security Authority who holds it. The type opens the policy for lookups only, so a plan can't change a right. Windows PowerShell 5.1 compiles it with `csc.exe`, which writes temporary files to the login's temp folder while it runs and deletes them after: three reads on Windows Server 2022 and 2025 left none behind.

## Removal

By default, deleting a `windows_user_right` step leaves the right as it is. With `on_remove = "delete"` it takes the right from the step's `principals`.
