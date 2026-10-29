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

**Creating.** A new user is created with `useradd -m`, which also creates its home directory. `system = true` adds `-r` for a system account, and only matters when the account is created.

**Changing.** When an existing account differs, Conn3x runs `usermod` with the attributes you set. Changing `home` this way updates the account but doesn't move the old directory's files.

**Groups.** `groups` is the complete list of supplementary groups, not an addition: Conn3x removes the user from any group you leave out. The groups have to exist already, so create them with [`group`](/modules/group) steps first; steps run in the order written.

**Names.** User and group names start with a lowercase letter or `_`, followed by up to 31 lowercase letters, digits, `-` or `_`. `home` and `shell` must be absolute paths. Conn3x checks these before connecting to the host.

## Removal

When you delete a `user` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the account. `"delete"` removes it with `userdel` and keeps its home directory.

## From Ansible

`conn3x convert ansible` turns `user` tasks into `user` steps, carrying over `uid`, `group`, `groups`, `home`, `shell` and `system`. Conn3x always creates a home directory for a new user, so a task with `create_home: no` stays a TODO. So does one with `append: true`, because `groups` in Conn3x is the full list, and so does one with `state: absent`.
