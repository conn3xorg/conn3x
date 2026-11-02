**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_user` to keep a local account on a Windows host: its name, full name, description, whether it's enabled, and its password. The password never reaches the plan or state.

## Example usage

```hcl
step "app_account" {
  windows_user {
    name        = "appsvc"
    full_name   = "App service"
    description = "Runs the app"
    password_wo = "use an ephemeral variable here"
  }
}
```

```hcl
step "no_guest" {
  windows_user {
    name     = "Guest"
    disabled = true
  }
}
```
<!-- reference -->
## How it works

Anything you leave unset is left as the host has it, so you can manage one setting on an account Windows made, such as `Guest`.

**Passwords.** `password_wo` goes to the host on stdin, never on a command line, and becomes a `SecureString` through .NET before any cmdlet sees it, so a logging policy that records cmdlet parameters records only the type name. State keeps a keyed hash, `password_hmac`. The password is set when the account is made and again whenever the value you give changes. Windows can't tell anyone a password, so a password changed on the host doesn't show as drift. Windows' own password policy applies: a password it refuses fails the apply with its message.

**No blank passwords.** Conn3x won't make or enable an account with no password, since Windows lets a blank password log on at the console. Give `password_wo`, or set `disabled = true`.

**The login.** Conn3x refuses to disable or delete the user it logs in as, checked by SID on the host, so it holds when the login's name comes from an SSH config file. Disabling that account ends key logins too. To stop a provisioning password being useful, change it with `password_wo` instead.

## Removal

By default, deleting a `windows_user` step leaves the account. With `on_remove = "delete"` it deletes the account and leaves its profile folder.
