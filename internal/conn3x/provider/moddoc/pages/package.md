Use `package` to install, upgrade or remove an operating system package with the host's own package manager: `dnf` on Rocky Linux, RHEL, AlmaLinux and Fedora, `zypper` on openSUSE and SUSE Linux Enterprise, `apt` on Debian and Ubuntu, and `apk` on Alpine.

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

**Reading.** On every plan, Conn3x asks the package database whether the package is installed and at which version: `rpm -q` on the Red Hat family and SUSE, `dpkg-query` on Debian and Ubuntu, and `apk list -I` on Alpine. On the Red Hat family it also accepts a package that provides the name, so `wget` matches `wget2-wget` on Fedora. With `state = "latest"`, it also reads the newest available version, from `dnf repoquery`, `zypper search`, `apt-cache policy` or `apk list`.

**Versions.** `version` matches the start of the installed version, so `"1.26.3"` matches `1:1.26.3-2.el10`. Give the epoch or the release as well when you need an exact match.

**Applying.** Conn3x runs `dnf -y install`, `upgrade` or `remove`, `apt-get install` or `remove` non-interactively, keeping existing configuration files, `zypper install`, `update` or `remove`, or `apk add --no-cache` and `apk del`. On SUSE, a `version` such as `1.7.0` installs the newest release of it, with `--oldpackage`, so a pin below the installed version downgrades, as Ansible's `zypper` does. zypper's exit 102, installed but a reboot is wanted, counts as success, and on 103, zypper updated itself, the command runs once more. 106, a repository that couldn't be refreshed, and 107, a package's install script failing, fail the step. `install_recommends` sets `--recommends` or `--no-recommends`, and `package_hold` is a zypper lock. A [`repository`](/modules/repository) step adds a zypper repository and imports its key, so a `package` step after it can install from it. On Alpine, `--no-cache` fetches the package index each time, so a fresh host needs no `apk update` first. A `version` there is a pin such as `2.2.1` or `2.2.1-r0`, which apk keeps in `/etc/apk/world`, and `install_recommends` is refused, since apk has no recommended packages. `package_hold`, `repository` and `package_sources` don't manage Alpine: pin with `version`, and keep `/etc/apk/repositories` with a `line` step. When another apt, dnf or zypper holds the package manager's lock, such as a step from another circuit on the same host or unattended upgrades on a host that just booted, Conn3x waits up to five minutes for it. When `apt` can't find a package on a fresh host, Conn3x refreshes the package lists once and tries again. If a mirror fails that refresh, with a timeout or an error such as a 403, Conn3x runs `apt-get update` again up to five times in all, waiting 1, 2, 4 and then 8 seconds, as Ansible's `apt` does with its `update_cache_retries`.

## Removal

When you delete a `package` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the package installed and stops managing it. `"delete"` uninstalls it.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.package`, `dnf`, `yum`, `apt`, `community.general.zypper` and `community.general.apk` tasks into `package` steps. `state: installed` and `removed` become `present` and `absent`, and `update_cache` is dropped, since Conn3x refreshes the package lists itself when a package isn't found. apt's `install_recommends` and dnf's `install_weak_deps` both become `install_recommends`, which sets apt's `APT::Install-Recommends` or dnf's `install_weak_deps` for the install. Ansible's zypper leaves recommended packages out unless `disable_recommends: false`, so a converted zypper step sets `install_recommends` to match. A zypper `type` other than `package`, such as a pattern or a patch, stays a TODO, and so does `state: dist-upgrade`.
