**Experimental.** Network devices are new, and this module may change between releases. It's tested against VyOS rolling in a container on a lab VM, not yet in CI.

Use `vyos_user` to keep a local account on a VyOS router: its full name, its password and its SSH keys. The change goes in like every VyOS step does, once per router per circuit; see [`vyos_config`](/modules/vyos_config).

Every VyOS account can configure the router, so treat each one as an admin.

The password never reaches the router or state as text. Conn3x hashes `password_wo` on your machine, sends the salted SHA-512 hash as `encrypted-password`, and keeps only an HMAC of that hash in state, so a refresh can tell whether the account still holds your password without knowing it. A password changed on the router by hand shows as drift.

`ssh_keys` is the account's whole set of keys: a key that isn't listed is deleted. VyOS files each key under a label; Conn3x uses the key's comment, such as `alice@laptop`, or a label made from the key itself when there's no usable comment, and matches keys by the key, whatever their label. Leave `ssh_keys` unset to leave the keys alone.

Conn3x won't delete the account it logs in as, or take all of its keys away. Removing the step deletes the account, as with every step that grants access, unless `on_remove = "forget"`.

## Example usage

Give the password from an ephemeral variable, so it stays out of state and plan files:

```hcl
step "alice" {
  vyos_user {
    name        = "alice"
    full_name   = "Alice Ops"
    password_wo = "use-an-ephemeral-variable-here"
    ssh_keys    = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@laptop"]
  }
}
```

## From Ansible

`conn3x convert ansible` turns `vyos.vyos.vyos_user` tasks into `vyos_user` steps, carrying over `full_name`, and `public_keys` as `ssh_keys`, one `type key name` line each. A `configured_password` isn't copied: the step gets a TODO to set `password_wo` from a secret. `encrypted_password`, `update_password: on_create`, `aggregate`, `purge` and `state: absent` stay TODOs.
