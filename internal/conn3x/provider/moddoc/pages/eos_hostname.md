**Experimental.** Network devices are new, and this module may change between releases. It's tested against cEOS-lab 4.37.0F on a local machine, not yet in CI.

Use `eos_hostname` to name an Arista EOS switch. The change goes through a config session with a revert timer, like every EOS step, including the wait before the confirm, which since v0.10.0 is paid once per switch per apply, not once per step; see [`eos_config`](/modules/eos_config).

## Example usage

```hcl
step "name" {
  eos_hostname {
    name = each.key
  }
}
```

## From Ansible

`conn3x convert ansible` turns `arista.eos.eos_hostname` tasks into `eos_hostname` steps, with `config.hostname` as `name`. `state: merged` and `replaced` convert; `deleted`, `overridden`, `gathered`, `rendered` and `parsed` stay TODOs. So does a name the step would refuse, with the step's own message, so it shows in the convert output instead of failing `conn3x validate` later.
