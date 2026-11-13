Use `sudoers` to give a user or group sudo rights to some commands, in a file of its own in `/etc/sudoers.d`. Conn3x checks the rule with `visudo` before it replaces anything, so a bad rule never stops sudo working for everyone.

## Example usage

Let the `deploy` group restart one service without a password:

```hcl
step "deploy_restart" {
  sudoers {
    name       = "deploy-restart"
    group      = "deploy"
    commands   = ["/usr/bin/systemctl restart app", "/usr/bin/systemctl status app"]
    nopassword = true
  }
}
```

Let `alice` run `psql` as `postgres`, with her password:

```hcl
step "alice_psql" {
  sudoers {
    name     = "alice-psql"
    user     = "alice"
    runas    = "postgres"
    commands = ["/usr/bin/psql"]
  }
}
```
<!-- reference -->
## How it works

**The file.** Each step writes one file, `/etc/sudoers.d/<name>`, owned by root with mode `0440`, holding one rule:

```text
%deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app, /usr/bin/systemctl status app
```

**Checking first.** The new content goes to a temporary file, and `visudo -cf` checks it. If `visudo` rejects it, the apply fails and the old file stays as it was.

**Reading.** On every plan, Conn3x reads the file. `in_sync` is true when it holds exactly the rule Conn3x writes, owned by root with mode `0440`. A hand edit shows as a change and is put back.

**Commands.** Each command starts with its absolute path, as sudo requires, followed by any arguments, or is `"ALL"`. Conn3x escapes the characters sudoers reads specially in a command: `,`, `:`, `=` and `\`.

**Rules.** `name` is letters, digits, `_` and `-`. sudo skips a file in `/etc/sudoers.d` whose name holds a dot or ends in `~`, so a name like `app.conf` would be a rule that silently does nothing. Set exactly one of `user` and `group`. `runas` is a user, `user:group`, or `ALL`, the default. `nopassword` defaults to false.

**Changes.** Changing anything but `name` rewrites the file. Changing `name` replaces the step, and `on_remove` decides what happens to the old file.

## Removal

When you delete a `sudoers` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the rule in place, so the user or group keeps the right. Set `"delete"` to remove the file when the step goes.

## From Ansible

`conn3x convert ansible` turns `community.general.sudoers` tasks with `state: present` into `sudoers` steps. Ansible's `nopassword` defaults to true and this step's to false, so a task that doesn't set it gets `nopassword = true` written out. `validation` is dropped: Conn3x always checks with `visudo`. A task with `setenv`, `noexec`, or a `sudoers_path` other than `/etc/sudoers.d` stays a TODO.
