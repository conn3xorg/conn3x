**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI.

Use `junos_hostname` to name a Juniper Junos device. The change goes in like every Junos step does: a dry run first, then `commit confirmed`, then a confirm over a new login, once per device per circuit. See [`junos_config`](/modules/junos_config).

## Example usage

```hcl
step "name" {
  junos_hostname {
    name = each.key
  }
}
```
