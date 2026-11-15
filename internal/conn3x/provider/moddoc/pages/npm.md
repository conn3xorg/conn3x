Use `npm` to keep a Node.js package installed: a CLI such as `pm2` in npm's global prefix, or one dependency of a project directory. Every plan asks `npm ls` what's installed, so someone upgrading a package by hand shows up in `conn3x drift`.

## Example usage

A global CLI, pinned:

```hcl
step "pm2" {
  npm {
    name    = "pm2"
    version = "5.4.2"
    global  = true
  }
}
```

A project's dependency, in a directory that's already there:

```hcl
step "left_pad" {
  npm {
    name    = "left-pad"
    version = "1.3.0"
    path    = "/opt/app"
  }
}
```

Keep a package at the newest version, and take one out:

```hcl
step "yarn" {
  npm {
    name   = "yarn"
    state  = "latest"
    global = true
  }
}
```

```hcl
step "old_client" {
  npm {
    name  = "old-client"
    state = "absent"
    path  = "/opt/app"
  }
}
```
<!-- reference -->
## How it works

**npm.** The host needs `node` and `npm` on the path, so put a [`package`](/modules/package) step for `nodejs` and `npm` first. Set `global = true` for a CLI, or `path` to a project directory, one or the other. The directory has to exist: make it with a [`directory`](/modules/directory) step. npm runs in it and keeps its `package.json` and `package-lock.json` up to date, so a step adds the package to the project, not only to `node_modules`.

**Who runs it.** A project install runs what the directory holds: its `.npmrc` picks the registry and the shell for scripts, and the packages' own install scripts run. So a step connected as root checks the path down to the directory first. One that belongs to a user runs as that user, with their permissions and npm settings, and what it installs belongs to them. One anyone can write to is refused, with the path and the reason. A global install runs as the connecting user.

**Versions.** `version` is one exact version, compared to what `npm ls` reports. Leave it out and any installed version is accepted, so the plan stays quiet whatever's there. `state = "latest"` asks the registry at every plan for the newest version, which takes network access. It settles until a new release comes out, then the plan shows the change.

**What isn't tracked.** Only the package you name, at the top of the tree. npm installs its dependencies at whatever versions fit, and a change to one isn't drift. A package `package.json` names but `node_modules` lacks reads as not installed.

**Changing a step.** Changing `version` or `state` installs in place, including going down a version. Changing `name`, `global` or `path` replaces the step.

## Removal

When you delete an `npm` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the package. `"delete"` uninstalls it, and in a project takes it out of `package.json` too.

## From Ansible

`conn3x convert ansible` turns `community.general.npm` tasks with a `name` into `npm` steps. `global`, `path`, `version` and `state` carry over, and `path` is dropped from a global install, where it changes nothing.

A task stays a TODO with the reason when:

- it has no `name`, since it then installs everything the project's `package.json` lists. Give each package a step
- `version` is a range or a tag, or `name` carries one
- it sets `executable`, `registry`, `production`, `ignore_scripts`, `unsafe_perm`, `ci`, `no_optional`, `no_bin_links` or `force`
- it's a loop, or `key=value` text

One thing differs. Ansible under `become` runs npm as root in a project directory whoever owns it; a step runs as the directory's owner, so what it installs belongs to them.
