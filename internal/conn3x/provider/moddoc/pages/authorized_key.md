Use `authorized_key` to let a public key log in as a user, by keeping one line in that user's `~/.ssh/authorized_keys`. Other keys in the file stay as they are, so several steps, or keys added by hand, can share one file.

## Example usage

Let a key log in as `alice`:

```hcl
step "alice_key" {
  authorized_key {
    user = "alice"
    key  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICb82CHmmk5O4gbUZUpj9cjkk0Lju2Grj2V76NeuFamL alice@laptop"
  }
}
```

Add several keys for one user, one instance per key and host:

```hcl
step "deploy_keys" {
  for_each = {
    ci     = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKcIIzM1rn1/TLenZvLoOhYMUDH09FQbF79aH8EBw8CM ci"
    backup = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIE5nhs+BwI3PWmCFy7xunil7netcw4nWH517PRzKtnK backup"
  }
  authorized_key {
    user = "deploy"
    key  = item.value
  }
}
```

Make sure a key can no longer log in:

```hcl
step "old_laptop" {
  authorized_key {
    user  = "alice"
    key   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDbDue/hPueZbuqhwN7+y5mw/e5UbAkjs9u4bV9pkskR old-laptop"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**Finding the file.** Conn3x looks the user up in the account database and uses `.ssh/authorized_keys` in their home directory. The user has to exist, so put the step after the [`user`](/modules/user) step that creates them.

**Matching keys.** Keys are compared by type and key data. A comment or options in front of the key don't count, so a key that's already there with a different comment is left as it is.

**Reading.** Every plan reads the file and checks whether the key is present, or absent with `state = "absent"`. If someone removed the key by hand, the plan shows the step out of sync and the next apply adds it back.

**Writing.** Conn3x creates `~/.ssh` with mode `0700` and `authorized_keys` with mode `0600`, both owned by the user and their primary group, as `sshd` requires. The file is written the same way as a [`file`](/modules/file) step: to a temporary file, then renamed into place.

**Validation.** `key` must be a single public key in `authorized_keys` format. Conn3x checks it before connecting to the host.

**Changing the key.** Changing `user` or `key` replaces the step. With the default `on_remove`, Conn3x removes the old key and adds the new one.

## Removal

When you delete an `authorized_key` step, `on_remove` decides what happens on the host. The default, `"delete"`, removes the key, so a key you rotate out stops working. `"forget"` leaves it in the file.

## From Ansible

`conn3x convert ansible` turns `authorized_key` tasks into `authorized_key` steps with `user` and `key`. A task with `state: absent`, or with other options such as `exclusive` or `key_options`, stays a TODO.
