Use `user` to create a local account and keep its user ID, groups, home directory and login shell as you set them. To let someone log in with an SSH key, add an [`authorized_key`](/modules/authorized_key) step after it.

## Example usage

Create a user with a login shell and supplementary groups:

```hcl
step "alice" {
  user {
    name   = "alice"
    shell  = "/bin/bash"
    groups = ["wheel"]
  }
}
```

Create a system account for a service, with a fixed ID and its own home:

```hcl
step "app_group" {
  group {
    name   = "app"
    gid    = 990
    system = true
  }
}

step "app_user" {
  user {
    name   = "app"
    uid    = 990
    group  = "app"
    home   = "/var/lib/app"
    shell  = "/usr/sbin/nologin"
    system = true
  }
}
```

Create several users, one instance per user and host:

```hcl
step "team" {
  for_each = ["alice", "bob", "carol"]
  user {
    name  = item.value
    shell = "/bin/bash"
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the account with `getent passwd`, its primary group's name with `getent group`, and its supplementary groups with `id -Gn`.

**What's managed.** Conn3x checks and sets only the attributes you give. Leave out `uid`, `group`, `groups`, `home` or `shell`, and Conn3x records what the host has and leaves it alone.

**Creating.** A new user is created with `useradd -m`, which also creates its home directory. `system = true` adds `-r` for a system account, and only matters when the account is created. `create_home = false` creates it with `useradd -M` instead, without a home directory, as a service account usually is. It also only matters at creation: a home directory that's already there is left alone, and changing it later changes nothing on the host.

**Comment.** `comment` is the account's comment, or GECOS, field: a full name or a description such as "Deploy user". It's read from `/etc/passwd`, so one changed by hand plans a change back, and it's set with `useradd -c` or `usermod -c`. It can't hold a colon or a line break, since `/etc/passwd` splits its fields on them. Leave it out and the field is left alone.

**Changing.** When an existing account differs, Conn3x runs `usermod` with the attributes you set. Changing `home` this way updates the account but doesn't move the old directory's files.

**Groups.** `groups` is the complete list of supplementary groups, not an addition: Conn3x removes the user from any group you leave out. With `append = true`, it's the groups the user must be in instead: Conn3x adds any it's missing with `usermod -a`, leaves the other groups the user is in alone, and plans a change only when one of yours is missing. Then state records only your groups. The groups have to exist already, so create them with [`group`](/modules/group) steps first; steps run in the order written.

**Passwords.** `password_wo` is write-only: it never reaches the plan or state, which keep only `password_hmac`, an HMAC keyed outside state, as for [`windows_user`](/modules/windows_user). Conn3x makes the `$6$` SHA-512 hash `/etc/shadow` holds and sets it with `chpasswd -e` on standard input, so the password never appears in the host's process list. The hash's salt comes from the HMAC key, the host and the user name: the same password always gives the same hash for one account, so a refresh can compare, and different hashes for every other account, so one `/etc/shadow` doesn't show who else shares a password. Every refresh reads the account's hash, so a password changed on the host plans a change, and the next apply puts it back. A locked account stays locked: the `!` that `passwd -l` and `usermod -L` put in front of the hash is left out of the comparison, so a locked account with the right password is in sync, and a new password is written behind the `!`. The step only locks or unlocks when you set `locked`. With `password_on_create = true`, the password is set only when the step creates the user, and never checked or changed after, as Ansible's `update_password: on_create` does. Reading `/etc/shadow` and running `chpasswd` need root, so a step with `password_wo` must log in as root or set `become` in its `ssh` block. Leave `password_wo` out and the password is left alone, and no longer read.

**Locking and expiry.** `locked = true` locks the password with `usermod -L`, which puts a `!` in front of its hash, and `locked = false` unlocks it with `usermod -U`, as Ansible's `password_lock` does. Locking stops password logins only: a user with an SSH key can still log in. A new account with no password counts as locked, and Conn3x refuses to unlock it, since that would leave an account anyone could log in to without a password: set `password_wo` or `password_hash_wo` with it. `expires` is the account's last day, as `YYYY-MM-DD` in UTC, and `""` means it never expires. After that day the account can't log in at all, by password or key. Every refresh reads both from `/etc/shadow`, so a lock or expiry changed by hand plans a change back. Leave either out and it's left alone and not read. Both need root, like the password: log in as root, or set `become` in the `ssh` block.

**A hash instead.** When you only have the hash, as an Ansible playbook's `password` is, give it as `password_hash_wo`, a crypt hash such as `openssl passwd -6` or `mkpasswd` prints. It's set as it is, and state keeps only its HMAC, so a password changed by hand plans a change back, as with `password_wo`. Set one of the two, not both. A value that isn't a crypt hash is refused, so a password given there by mistake is never set. `password_on_create` works with it too.

**Names.** User and group names start with a lowercase letter or `_`, followed by up to 31 lowercase letters, digits, `-` or `_`. `home` and `shell` must be absolute paths. Conn3x checks these before connecting to the host.

## Removal

When you delete a `user` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the account. `"delete"` removes it with `userdel` and keeps its home directory.

## From Ansible

`conn3x convert ansible` turns `user` tasks into `user` steps, carrying over `uid`, `group`, `groups`, `home`, `shell`, `comment`, `system`, and `create_home: false` (or its older name, `createhome`). `append: true` becomes `append = true`. A task with `state: absent` stays a TODO, as does one with a `uid` that isn't a whole number. `password_lock` becomes `locked`, and `expires`, seconds since 1970, becomes the date it falls on in UTC, as Ansible compares it; a negative one becomes `""`. An `expires` that isn't a number stays a TODO. A task with `password` converts with a TODO to set `password_hash_wo`, since Ansible's is already a hash. The hash isn't copied into the circuit. With `update_password: on_create`, the TODO also says to add `password_on_create = true`.
