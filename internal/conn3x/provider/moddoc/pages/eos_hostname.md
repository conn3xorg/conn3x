**Experimental.** Network devices are new, this module may change between releases, and it hasn't yet run against a switch in our CI.

Use `eos_hostname` to name an Arista EOS switch. The change goes through a config session with a revert timer, like every EOS step; see [`eos_config`](/modules/eos_config).

## Example usage

```hcl
step "name" {
  eos_hostname {
    name = each.key
  }
}
```
