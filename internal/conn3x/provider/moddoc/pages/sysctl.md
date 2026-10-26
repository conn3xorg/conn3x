Use `sysctl` to set a kernel parameter on a host. Conn3x sets the value in the running kernel and writes it to a file in `/etc/sysctl.d`, so it survives a reboot.

## Example usage

Turn on IP forwarding:

```hcl
step "ip_forward" {
  sysctl {
    name  = "net.ipv4.ip_forward"
    value = "1"
  }
}
```

Set several parameters, one instance per parameter and host:

```hcl
step "kernel" {
  for_each = {
    "vm.swappiness"               = "10"
    "net.core.somaxconn"          = "4096"
    "fs.inotify.max_user_watches" = "524288"
  }
  sysctl {
    name  = item.key
    value = item.value
  }
}
```

Give a parameter that takes several values, separated by spaces:

```hcl
step "port_range" {
  sysctl {
    name  = "net.ipv4.ip_local_port_range"
    value = "32768 60999"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the parameter's file in `/etc/sysctl.d` and the running value from `sysctl -n`. `in_sync` is true only when both match. Runs of spaces and tabs in a value compare as a single space, so `"32768 60999"` matches however the kernel prints it.

**Applying.** Conn3x writes `/etc/sysctl.d/90-conn3x-<name>.conf`, owned by root with mode `"0644"`, then loads it with `sysctl -p`. A `/` in the name, as in an interface name such as `eth0/100`, becomes `_` in the file name.

**Reboots.** The host loads the files in `/etc/sysctl.d` at boot, so the value comes back after a reboot.

**Changes.** Changing `value` updates the file and the running kernel. Changing `name` replaces the step: Conn3x writes a new file for the new name, and `on_remove` decides what happens to the old one.

## Removal

When you delete a `sysctl` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file and the value in place. `"delete"` removes the file. The running kernel keeps the value until the next reboot.

## From Ansible

`conn3x convert ansible` turns `ansible.posix.sysctl` tasks into `sysctl` steps. `reload` and `sysctl_set` are dropped, since Conn3x always sets the running value. A task with `sysctl_file`, or with a `state` other than `present`, stays a TODO.
