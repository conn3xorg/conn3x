**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_ad_user` to keep a user in Active Directory. Run it on a domain controller. Groups aren't set here: list the user in a [`windows_ad_group`](windows_ad_group.md) step's `members`.

## Example usage

```hcl
step "alice" {
  windows_ad_user {
    name         = "alice"
    path         = "OU=Lab,DC=lab,DC=example,DC=com"
    upn          = "alice@lab.example.com"
    given_name   = "Alice"
    surname      = "Smith"
    display_name = "Alice Smith"
    password_wo  = "use an ephemeral variable here"
  }
}
```

A service account whose password shouldn't expire:

```hcl
step "svc_backup" {
  windows_ad_user {
    name                   = "svc-backup"
    description            = "Runs the nightly backup"
    password_never_expires = true
    password_wo            = "use an ephemeral variable here"
  }
}
```
<!-- reference -->
## How it works

**Names.** `name` is the logon name, the sAMAccountName, up to 20 characters. The user is found by it anywhere in the domain, and it's also the user's name in the directory. If the user is in another OU and `path` is set, apply moves it.

**The password.** `password_wo` goes to the domain controller on stdin and becomes a `SecureString` through .NET before any cmdlet sees it, so a logging policy that records cmdlet parameters records only the type name. It's never in plan or state, and it's blanked from errors. State keeps an HMAC of it, so a new password plans a change and the same one doesn't. A password someone resets in the domain isn't detected, because it can't be read back.

**Enabled.** A new user with `password_wo` is enabled, and one without stays disabled, as Windows would have it. It's made disabled first and enabled only once the password is set. `enabled = true` with no password ever set is refused. Conn3x won't disable or delete the user it logs in as.

**Drift.** A refresh reads the location, UPN, names, description, whether the account is enabled and whether its password expires. Change any of those by hand and the next plan shows the step out of sync, and `conn3x drift` exits 2. Settings you leave unset aren't compared.

**Reads change nothing.** A refresh runs `Get-ADObject` and `Get-ADUser` only. Nothing about the password comes back but whether one was ever set.

## Removal

By default, deleting a `windows_ad_user` step leaves the user. With `on_remove = "delete"` it deletes the user, unless it's the one Conn3x logs in as.
