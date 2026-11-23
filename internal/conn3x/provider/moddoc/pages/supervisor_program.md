Use `supervisor_program` for an app that runs under supervisord rather than systemd, as plenty of older Python, PHP and Ruby apps still do. It keeps one program, or one group, loaded and running or stopped, through `supervisorctl`. It's `community.general.supervisorctl` with the states and none of the actions.

## Example usage

Write the program's file, then keep it running, and pick up a change to the file:

```hcl
step "app_conf" {
  file {
    path    = "/etc/supervisor/conf.d/app.conf"
    content = "[program:app]\ncommand=/opt/app/bin/serve\nautostart=true\n"
  }
}

step "app" {
  supervisor_program {
    name     = "app"
    state    = "started"
    triggers = { conf = conn3x_file.docs__app_conf[each.key].revision }
  }
}
```

The address is the step's resource address, `conn3x_file.CIRCUIT__STEP`, here in a circuit named `docs`.

Keep a group of workers stopped, through supervisord's HTTP server:

```hcl
step "workers" {
  supervisor_program {
    name       = "workers:"
    state      = "stopped"
    server_url = "http://127.0.0.1:9001"
  }
}
```
<!-- reference -->
## How it works

**Names.** `name` is a program, such as `app`, or a group with a trailing colon, such as `workers:`, the way `supervisorctl` takes them. A group's state covers every process in it. `all` isn't accepted: give each program its own step.

**States.** `started` starts the program when it isn't running, and `stopped` stops it when it is. Starting, running and backing off all count as running, as they do in Ansible. `present` only makes sure supervisord has it loaded and leaves it running or stopped. `absent` stops it and removes it from supervisord.

**Loading.** When supervisord doesn't know the program yet, the step runs `supervisorctl reread` and `add` first. `add` starts a program with `autostart=true`, so `state = "stopped"` stops it again straight after.

**Drift.** Every refresh runs `supervisorctl status NAME`. A program someone stopped by hand, or one that crashed into `FATAL`, shows as out of sync, and `processes` shows each process's state. The next apply starts it again.

**A changed file.** The program's `[program:x]` file is a `file` step, as it is in Ansible. Give its revision to `triggers` and whenever it changes the step runs `supervisorctl update` for the program, which rereads the file, then restarts it when `state` is `started`. So a trigger on new code, under an unchanged file, restarts the program too. With `stopped` or `present`, only `update` runs, so a program meant to stay stopped isn't started.

**Reaching supervisord.** `config` and `server_url` go to `supervisorctl` as `-c` and `-s`. Unset, `supervisorctl` reads its own configuration, `/etc/supervisor/supervisord.conf` on Debian and Ubuntu.

**A login.** When supervisord asks for a username and password, the step doesn't take them. Every refresh would need them, so they'd sit in state, and `supervisorctl -p` shows the password to anyone running `ps`. Put them in the `[supervisorctl]` section of a file only root can read, and point `config` at it:

```ini
[supervisorctl]
serverurl = http://127.0.0.1:9001
username  = admin
password  = s3cret
```

Write that file with a `file` step whose content comes from a write-only or ephemeral value, so the password never reaches state there either. `server_url` can't carry a login, as in `http://admin:pw@host`, for the same reason.

**The tools.** `supervisorctl` comes with the `supervisor` package. When it's missing, the step says so. Put a `package` step before it.

## Removal

`on_remove = "forget"`, the default, leaves the program as it is. `on_remove = "delete"` stops it and removes it from supervisord. Neither touches the program's file.
