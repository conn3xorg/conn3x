Use `selinux_mode` to put a host in enforcing or permissive mode and keep it there across reboots. It's the switch most teams flip with `setenforce` and an edit to `/etc/selinux/config`, done once and then forgotten on half the fleet. SELinux is on by default across the Red Hat family, such as Rocky Linux and RHEL.

## Example usage

Keep a host enforcing:

```hcl
step "selinux" {
  selinux_mode {
    mode = "enforcing"
  }
}
```

Run permissive while you write the policy for a new app, then switch back by changing one word:

```hcl
step "selinux" {
  selinux_mode {
    mode = "permissive"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the `SELINUX=` line in `/etc/selinux/config` and the running mode from `/sys/fs/selinux/enforce`. `in_sync` is true when the file has `mode` and, while SELinux is on, the host is running in it. If the host has no `/etc/selinux/config`, the step fails, since SELinux isn't installed there.

**Applying.** Conn3x sets the `SELINUX=` line and keeps the rest of the file, `SELINUXTYPE` included. The file keeps its mode, and its SELinux label is restored after the write. While SELinux is on, `setenforce` switches the running mode too, so the change takes effect without a reboot.

**When SELinux is off.** `setenforce` can't turn SELinux on, so on a host where it's disabled Conn3x writes the file and sets `reboot_required` to true. The mode takes effect at the next boot. Pair the step with a [reboot](/modules/reboot) step for those hosts.

**Disabling.** `mode` takes `enforcing` or `permissive`. Turning SELinux off isn't here yet. Permissive logs what it would deny and blocks nothing, which is usually what you're after.

**Changes.** Changing `mode` updates the host in place. There's one `selinux_mode` per host.

## Removal

A `selinux_mode` step has no `on_remove`. When you delete it, Conn3x stops managing the mode and leaves it as it is.
