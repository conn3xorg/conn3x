Use `selinux_boolean` to turn an SELinux boolean on or off, now and across reboots. Booleans switch optional parts of the SELinux policy, such as letting a web server make network connections. They apply on hosts with SELinux enabled, which in practice means the Red Hat family.

## Example usage

Let the web server connect to a backend over the network:

```hcl
step "httpd_network" {
  selinux_boolean {
    name  = "httpd_can_network_connect"
    value = true
  }
}
```

Set several booleans, one instance per boolean and host:

```hcl
step "booleans" {
  for_each = {
    httpd_can_network_connect_db = true
    httpd_enable_homedirs        = false
  }
  selinux_boolean {
    name  = item.key
    value = item.value
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the boolean's current value from `/sys/fs/selinux/booleans`. `in_sync` is true when it matches `value`. If SELinux isn't enabled on the host, the step fails.

**Applying.** Conn3x runs `setsebool -P`, which sets the running value and writes it to the policy, so it holds across reboots.

**Changes.** Changing `value` updates the boolean in place. Changing `name` replaces the step; the old boolean keeps its value.

## Removal

A `selinux_boolean` step has no `on_remove`. When you delete it, Conn3x stops managing the boolean and leaves its value as it is.

## From Ansible

`conn3x convert ansible` turns `ansible.posix.seboolean` tasks into `selinux_boolean` steps, with `state` becoming `value`. A task without `persistent: true` stays a TODO, since Conn3x always makes the change persistent.
