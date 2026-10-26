Use `hostname` to set a host's name, both in the running system and in `/etc/hostname`, so it holds across reboots. A host has one name, so a circuit needs only one `hostname` step.

## Example usage

Name every host after its key in the circuit's `hosts` map:

```hcl
step "hostname" {
  hostname {
    name = each.key
  }
}
```

Set a fully qualified name:

```hcl
step "fqdn" {
  hostname {
    name = "${each.key}.example.com"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads `/etc/hostname` and the running name from `uname -n`. `in_sync` is true only when both equal `name`.

**Applying.** Conn3x runs `hostnamectl set-hostname`, which sets the running name and writes `/etc/hostname`. It doesn't change `/etc/hosts`; manage that with a [`line`](/modules/line) step if you need the name to resolve locally.

**Names.** `name` must be 1 to 64 characters, made of dot-separated labels of letters, digits and inner hyphens. Conn3x checks this before it connects to the host.

**Cloud images.** cloud-init may set the name again at boot. Set `preserve_hostname: true` in its configuration to stop that.

## Removal

A `hostname` step has no `on_remove`. When you delete it, Conn3x stops managing the name and leaves the host as it is.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.hostname` tasks into `hostname` steps. `use` is dropped, since Conn3x always uses `hostnamectl`.
