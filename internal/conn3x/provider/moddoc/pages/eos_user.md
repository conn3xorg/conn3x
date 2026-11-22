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

EOS stores a password as a salted hash. Conn3x works that hash out on your machine and sends the switch `secret sha512 <hash>`, so the password itself never reaches the switch's CLI or a config session. State keeps neither: `password_hmac` is an HMAC of the hash, keyed outside state. A new password plans a change through it, and every refresh compares the hash on the switch with it, so an account that holds another password shows as out of sync and the next apply sets yours. That covers an account that was on the switch before the step, a password changed by hand, and an apply that stopped before its commit. Changing the role or privilege keeps the password as it is on the switch. Leave `password_wo` unset to leave the password alone.

A new account without `password_wo` gets `secret *`, a secret no password matches, so it logs in with its SSH key only. EOS's own `nopassword` lets an account in with an empty password wherever the switch takes password logins, the console included, so Conn3x writes it only when you ask with `nopassword = true`. Set `nopassword = false` to close an account that has it. Conn3x up to v0.11.0 made key-only accounts with `nopassword`; a refresh warns about each one until you choose.

Refreshing needs the HMAC key that made `password_hmac`. On a machine without it, a refresh can only tell that the account has a secret, not which.

Hashes are masked in every log line and error Conn3x writes. The log lists the lines Conn3x added to the session, never the switch's own diff of it, which would show the config around them. OpenTofu itself logs its command line, so pass a password through a variable file or `TF_VAR_`, not `-var`.

Conn3x won't lower the privilege or change the role of the account it logs in as, and won't delete it.

## Removal

`on_remove` defaults to `"delete"`: removing the step deletes the account, as with every step that grants access. Set `"forget"` to leave it.

## From Ansible

`conn3x convert ansible` turns `arista.eos.eos_user` tasks into `eos_user` steps, carrying over `role`, `privilege`, `nopassword`, and `sshkey` as `ssh_key`. A `configured_password` isn't copied: the step gets a TODO to set `password_wo` from a secret. `aggregate`, `purge`, `state: absent` and `update_password: on_create` stay TODOs.
