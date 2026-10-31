Use `pip` to keep a Python package at a known version in a virtual environment, built for you if it's missing. Every plan asks the venv's own pip what's installed, so someone upgrading a package by hand shows up in `conn3x drift`.

## Example usage

Pin a package in a venv Conn3x builds:

```hcl
step "requests" {
  pip {
    name    = "requests"
    version = "2.32.3"
    venv    = "/opt/app/venv"
  }
}
```

Pin a few together, in a venv in a user's home:

```hcl
step "app_packages" {
  for_each = { django = "5.2.1", gunicorn = "23.0.0" }
  pip {
    name    = item.key
    version = item.value
    venv    = "/home/app/venv"
    user    = "app"
  }
}
```

Keep a package at the newest version, and take one out:

```hcl
step "certifi" {
  pip {
    name  = "certifi"
    state = "latest"
    venv  = "/opt/app/venv"
  }
}
```

```hcl
step "old_client" {
  pip {
    name  = "old-client"
    state = "absent"
    venv  = "/opt/app/venv"
  }
}
```
<!-- reference -->
## How it works

**The venv.** A missing venv is built with `python3 -m venv`, and so is one whose Python or pip no longer runs. The host needs `python3` for that. On Debian and Ubuntu it also needs `python3-venv`, so put a [`package`](/modules/package) step first. `state = "absent"` never builds one. There's no system-wide install: `venv` is required, because pip packages outside one fight the OS's own, and current distros refuse them.

**Who runs it.** Everything runs as `user`, or as the connecting user without it. Before running anything from the venv, Conn3x checks the path down to it and everything inside it, because whoever can write there picks the code that runs next. Each one has to belong to root or the running user, and nobody else may be able to write to it. Fail that, and the step stops with the path and the reason, before any of the venv's code runs. So a step connected as root can't reach into `/home/app`: set `user = "app"`, and it works with that user's permissions and pip settings, and what it builds belongs to them.

**Versions.** `version` is one exact version, compared the way pip's `==` does, so `1.2` and `1.2.0` are the same. Leave it out and any installed version is accepted, so the plan stays quiet whatever's there. `state = "latest"` asks pip at every plan what an upgrade would install, which takes network access and pip 22.2 or later. It settles until a new release comes out, then the plan shows the change.

**What isn't tracked.** Only the package you name. pip installs its dependencies at whatever versions fit, and leaves them behind when you remove it, and a change to a dependency isn't drift. If those versions matter, give each one a step. Installing can run the package's own build code as the running user, one more reason to set `user`.

**Changing a step.** Changing `version` or `state` installs in place, including going down a version. Changing `name`, `venv` or `user` replaces the step.

## Removal

When you delete a `pip` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the package. `"delete"` uninstalls it. The venv stays either way.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.pip` tasks with a `virtualenv` into `pip` steps, one for each name. `name: six==1.16.0` and `version: "1.16.0"` both become `version`. `state` can be `present`, `latest` or `absent`.

A task stays a TODO with the reason when:

- it has no `virtualenv`, since a `pip` step doesn't install system-wide
- it uses `requirements`, because that file is on the host and the converter can't see what it pins. Give each package a step with its version
- `name` is a range such as `six>=1`, or has extras, a URL or a path
- `virtualenv` isn't an absolute path, or is under `/home` or `/root`, where Ansible may have built it as root and a step won't run. Set `user` by hand
- it sets `state: forcereinstall`, which never settles, or `extra_args`, `executable`, `chdir`, `umask`, `virtualenv_python`, `virtualenv_site_packages` or `editable`
- `virtualenv_command` is anything but `virtualenv` or `python3 -m venv`
- it's a loop, or `key=value` text, or the play sets `become_user`, or `remote_user` without `become`

Three things differ and can't be seen from the playbook. Ansible builds a missing venv with the `virtualenv` tool unless told otherwise, and fails if that isn't installed, where Conn3x uses `python3 -m venv`, so the venv's seed packages can differ. Ansible builds a missing venv even for `state: absent`, and Conn3x leaves it missing. And a step refuses a venv another user could change, where Ansible runs it anyway: a play under `become` with `/opt/app` owned by `app` needs `user = "app"` on the step.
