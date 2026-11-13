**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI.

Use `junos_user` to keep a local account on a Juniper Junos device: its login class, its password and its SSH keys. The change goes in like every Junos step does, once per device per circuit; see [`junos_config`](/modules/junos_config).

The password never reaches the device or state as text. Conn3x hashes `password_wo` on your machine, sends the salted SHA-512 hash as `encrypted-password`, and keeps only an HMAC of that hash in state, so a refresh can tell whether the account still holds your password without knowing it. A password changed on the device by hand shows as drift.

`ssh_keys` is the account's whole set of keys: a key that isn't listed is deleted. Leave it unset to leave the keys alone.

Conn3x won't delete the account it logs in as, or move it out of `super-user`. Removing the step deletes the account, as with every step that grants access, unless `on_remove = "forget"`.

## Example usage

Give the password from an ephemeral variable, so it stays out of state and plan files:

```hcl
step "alice" {
  junos_user {
    name        = "alice"
    class       = "operator"
    password_wo = "use-an-ephemeral-variable-here"
    ssh_keys    = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnlyForDocs alice@laptop"]
  }
}
```
