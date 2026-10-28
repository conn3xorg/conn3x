Use `package` to install, upgrade or remove an operating system package with the host's own package manager: `dnf` on Rocky Linux, RHEL, AlmaLinux and Fedora, and `apt` on Debian and Ubuntu.

## Example usage

Install a package:

```hcl
step "nginx" {
  package {
    name = "nginx"
  }
}
```

Install several packages, one instance per package and host:

```hcl
step "tools" {
  for_each = ["git", "jq", "tree"]
  package {
    name = item.value
  }
}
```

Pin a version, keep a package at the newest available version, or remove one:

```hcl
step "pinned" {
  package {
    name    = "nginx"
    version = "1.26.3"
  }
}

step "current" {
  package {
    name  = "curl"
    state = "latest"
  }
}

step "gone" {
  package {
    name  = "telnet"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks the package database whether the package is installed and at which version: `rpm -q` on the Red Hat family and `dpkg-query` on Debian and Ubuntu. On the Red Hat family it also accepts a package that provides the name, so `wget` matches `wget2-wget` on Fedora. With `state = "latest"`, it also reads the newest available version, from `dnf repoquery` or `apt-cache policy`.

**Versions.** `version` matches the start of the installed version, so `"1.26.3"` matches `1:1.26.3-2.el10`. Give the epoch or the release as well when you need an exact match.

**Applying.** Conn3x runs `dnf -y install`, `upgrade` or `remove`, or `apt-get install` or `remove` non-interactively, keeping existing configuration files. When another apt or dnf holds the package manager's lock, such as a step from another circuit on the same host or unattended upgrades on a host that just booted, Conn3x waits up to five minutes for it. When `apt` can't find a package on a fresh host, Conn3x refreshes the package lists once and tries again.

## Removal

When you delete a `package` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the package installed and stops managing it. `"delete"` uninstalls it.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.package`, `dnf`, `yum` and `apt` tasks into `package` steps. `state: installed` and `removed` become `present` and `absent`, and `update_cache` is dropped, since Conn3x refreshes the package lists itself when a package isn't found.
