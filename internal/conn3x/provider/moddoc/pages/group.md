Use `group` to create a local group and, if you choose, pin its group ID. Create groups before the [`user`](/modules/user) steps that put people in them.

## Example usage

Create a group:

```hcl
step "developers" {
  group {
    name = "developers"
  }
}
```

Create a system group with a fixed ID:

```hcl
step "app_group" {
  group {
    name   = "app"
    gid    = 990
    system = true
  }
}
```

Create several groups, one instance per group and host:

```hcl
step "groups" {
  for_each = ["developers", "operators", "auditors"]
  group {
    name = item.value
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the group with `getent group` and records its ID.

**Applying.** A new group is created with `groupadd`, with `-g` when you set `gid` and `-r` when you set `system = true`. `system` only matters when the group is created. If the group exists with a different ID than `gid`, Conn3x changes it with `groupmod -g`. Leave out `gid` and Conn3x keeps whatever ID the host gave the group.

**Names.** Group names start with a lowercase letter or `_`, followed by up to 31 lowercase letters, digits, `-` or `_`. Conn3x checks this before connecting to the host.

## Removal

When you delete a `group` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the group. `"delete"` removes it with `groupdel`.

## From Ansible

`conn3x convert ansible` turns `group` tasks into `group` steps, carrying over `gid` and `system`. A task with `state: absent` stays a TODO.
