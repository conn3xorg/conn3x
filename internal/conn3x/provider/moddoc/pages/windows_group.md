**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_group` to keep a local group on a Windows host and make sure the right accounts are in it. Members are compared by SID, so `LAB\alice` and `lab\Alice` are the same account.

## Example usage

```hcl
step "app_admins" {
  windows_group {
    name        = "AppAdmins"
    description = "Can manage the app"
    members     = ["appsvc", "LAB\\alice"]
  }
}
```

```hcl
step "rdp_only_ops" {
  windows_group {
    name          = "Remote Desktop Users"
    members       = ["LAB\\ops"]
    authoritative = true
  }
}
```
<!-- reference -->
## How it works

**Members.** By default, `members` are added and nobody else is taken out. With `authoritative = true` the list is complete: anyone else is removed on apply. In a group the login Conn3x uses belongs to, such as `Administrators`, Conn3x refuses to remove the login or any group it gets its rights through, such as `Domain Admins`, so apply fails until the list keeps them.

A member that doesn't exist yet, such as a user a later step makes, shows the group as out of sync rather than failing the plan. At apply, a name that still doesn't resolve is an error.

## Removal

By default, deleting a `windows_group` step leaves the group and its members. With `on_remove = "delete"` it deletes the group.
