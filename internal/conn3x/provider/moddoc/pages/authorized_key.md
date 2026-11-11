Use `authorized_key` to let a public key log in as a user, by keeping one line in that user's `~/.ssh/authorized_keys`. Other keys in the file stay as they are, so several steps, or keys added by hand, can share one file. With `exclusive`, one step lists every key the user may log in with, and any other is removed.

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

Let only these keys log in as `deploy`, and remove any other:

```hcl
step "deploy_keys" {
  authorized_key {
    user      = "deploy"
    exclusive = true
    key       = <<-EOT
      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKcIIzM1rn1/TLenZvLoOhYMUDH09FQbF79aH8EBw8CM ci
      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIE5nhs+BwI3PWmCFy7xunil7netcw4nWH517PRzKtnK backup
    EOT
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

**Keeping only these keys.** With `exclusive = true`, `key` holds every key the user may log in with, one per line, and Conn3x makes `authorized_keys` exactly those:
- **Removing the rest:** a key that isn't listed is removed, and so is a line Conn3x can't read as a key, since `sshd` might still take it. Listed keys that are already there stay as they are, with their options and comments. Blank lines and `#` comments stay too.
- **The plan:** every plan reads the file, and the step's `unlisted` holds each key it would remove, by type and SHA-256 fingerprint. The plan shows them going, and a warning names them with their comments. The comments aren't kept in state, since they're often email addresses.
- **Changing the list:** adding or removing a key is an update, not a replacement, so the step never removes the old keys first.
- **The key Conn3x logs in with:** if `user` is the account Conn3x logs in as, and the key that logged it in isn't listed, the apply is refused, because the next run couldn't log in.
  - **Options:** the check compares keys, not their options. A listed login key with a `from=` that leaves out the address Conn3x connects from still locks it out, as it would without `exclusive`.
  - **Certificates:** if Conn3x logs in with an SSH certificate, an exclusive step for that account is refused. `sshd` trusts a certificate through its CA, not through a line for the key, so there's nothing in the list to check it against. Log in as another account to make this one's keys exclusive.
- **Two steps for one user:** a circuit can't have an exclusive step and another `authorized_key` step for the same `user`, or an exclusive step with `for_each`, since each would remove the other's keys on every apply. That's checked when `user` is written out, such as `"deploy"`. Two steps whose `user` is computed, from a variable or `each.value`, aren't checked, so keep each user's keys in one step.
- **Not with `state = "absent"`.**

Conn3x reads and writes `~/.ssh` as the user whose keys it's managing, so a symlink that user planted gets them nothing they couldn't already reach. That means the user has to be able to write there: a `~/.ssh` owned by root, or a home the user can't write to, gives an error. See [GHSA-78rx-v8vx-rjhg](https://github.com/conn3xorg/conn3x/security/advisories/GHSA-78rx-v8vx-rjhg).

## Removal

When you delete an `authorized_key` step, `on_remove` decides what happens on the host. The default, `"delete"`, removes the key, so a key you rotate out stops working. `"forget"` leaves it in the file.

An exclusive step defaults to `"forget"` and can't be set to `"delete"`: removing every key it lists would lock out everyone it was keeping in. The file stays as the step last left it.

## From Ansible

`conn3x convert ansible` turns `authorized_key` tasks into `authorized_key` steps with `user` and `key`. `exclusive: true` carries over as it is: like Ansible's, it keeps only that one task's keys, which `key` may hold one per line. A task with `state: absent`, or with other options such as `key_options`, stays a TODO.
