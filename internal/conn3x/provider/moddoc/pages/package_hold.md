Use `package_hold` to keep a package at the version it has while the rest of the host updates, such as the kernel on a host with a driver built for it, or a database you upgrade by hand. It's `apt-mark hold` on Debian and Ubuntu and `dnf versionlock` on the Red Hat family. It doesn't install anything: put a [`package`](package.md) step first if the package isn't there yet.

## Example usage

Hold PostgreSQL where it is:

```hcl
step "postgres" {
  package {
    name = "postgresql16-server"
  }
}

step "postgres_held" {
  depends_on = [conn3x_package.db__postgres]

  package_hold {
    name = "postgresql16-server"
  }
}
```

On Rocky Linux, AlmaLinux and RHEL, `dnf versionlock` is a plugin. Install it first:

```hcl
step "versionlock" {
  package {
    name = "python3-dnf-plugin-versionlock"
  }
}
```

Let it update again, when you're ready:

```hcl
step "postgres_held" {
  package_hold {
    name  = "postgresql16-server"
    state = "released"
  }
}
```
<!-- reference -->
## How it works

**Holding.** On the Debian family, Conn3x runs `apt-mark hold`, and `apt-mark unhold` to release. On the Red Hat family it runs `dnf versionlock add`, which locks the version that's installed, or the newest available one if the package isn't installed, and `dnf versionlock delete` to release. Fedora's dnf 5 has `versionlock` built in. dnf 4, on Rocky Linux 10, AlmaLinux and RHEL, needs `python3-dnf-plugin-versionlock`, and without it the step fails and names that package.

**Reading.** Every plan reads `apt-mark showhold` or `dnf versionlock list`. A hold someone released by hand, or one someone added, shows the step out of sync, and the next apply puts it back the way the step says. Apply changes nothing when the host already matches.

**What a hold does.** `apt upgrade` and `dnf upgrade` leave a held package at its version, so a routine update, by hand, by `unattended-upgrades` or by `dnf-automatic`, can't move it. To move it on purpose, release it, upgrade, and hold it again.

## Removal

Deleting a `package_hold` step leaves the hold as it is. With `on_remove = "delete"`, it releases it.
