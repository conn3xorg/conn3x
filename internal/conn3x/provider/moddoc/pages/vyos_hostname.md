**Experimental.** Network devices are new, and this module may change between releases. It's tested against VyOS 2026.11.13-0016-rolling in a container on a lab VM, not yet in CI.

Use `vyos_hostname` to name a VyOS router. The change goes in like every VyOS step does: a dry run, `commit-confirm`, then a confirm and save over a new login, once per router per circuit. See [`vyos_config`](/modules/vyos_config).

## Example usage

```hcl
step "name" {
  vyos_hostname {
    name = each.key
  }
}
```
