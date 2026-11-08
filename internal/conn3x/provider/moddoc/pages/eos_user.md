**Experimental.** Network devices are new, and this module may change between releases. It's tested against cEOS-lab 4.37.0F on a local machine, not yet in CI, so try it on a lab switch first.

Use `eos_user` to keep a switch's local accounts in your circuit: who exists, with what role and privilege, which SSH key, and a password that never lands in state. Onboarding an engineer is a step; offboarding is deleting it.

## Example usage

An operator who logs in with a key only:

```hcl
step "alice" {
  eos_user {
    name    = "alice"
    role    = "network-operator"
    ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPqYlxRpTzmq5d0Xgq9Fh0oQn0vMZ8b7T5w1P8kJZx2Q alice@laptop"
  }
}
```

An admin with a password. Give it from an ephemeral variable, so it stays out of state and plan files:

```hcl
step "breakglass" {
  eos_user {
    name        = "breakglass"
    privilege   = 15
    role        = "network-admin"
    password_wo = "use-an-ephemeral-variable-here"
  }
}
```
<!-- reference -->
## How it works

EOS stores a password as a salted hash, so Conn3x can only tell that an account has one, never which. It keeps an HMAC of `password_wo` in `password_hmac`, keyed outside state, and a new password plans a change through it. Changing the role or privilege keeps the password as it is on the switch. Leave `password_wo` unset to leave the password alone; a new account then gets none (`nopassword`), for key-only logins. A password can't hold spaces, since the EOS CLI would read the rest as more of the command.

Passwords and their hashes are masked in every log line and error Conn3x writes, the session diff included. OpenTofu itself logs its command line, so pass a password through a variable file or `TF_VAR_`, not `-var`.

Conn3x won't lower the privilege or change the role of the account it logs in as, and won't delete it.

## Removal

`on_remove` defaults to `"delete"`: removing the step deletes the account, as with every step that grants access. Set `"forget"` to leave it.
