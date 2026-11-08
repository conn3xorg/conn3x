**Experimental.** Network devices are new, and this module may change between releases. It's tested against cEOS-lab 4.37.0F on a local machine, not yet in CI.

Use `eos_hostname` to name an Arista EOS switch. The change goes through a config session with a revert timer, like every EOS step, including the wait before the confirm: about 30 seconds per step in v0.9.0, and once per switch from the next release; see [`eos_config`](/modules/eos_config).

## Example usage

```hcl
step "name" {
  eos_hostname {
    name = each.key
  }
}
```
