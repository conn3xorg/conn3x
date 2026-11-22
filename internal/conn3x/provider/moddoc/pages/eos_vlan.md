**Experimental.** Network devices are new, and this module may change between releases. It's tested against cEOS-lab 4.37.0F on a local machine, not yet in CI.

Use `eos_vlan` to create a VLAN on an Arista EOS switch and give it a name. Removing the step deletes the VLAN, unless `on_remove = "forget"`. The change goes through a config session with a revert timer, like every EOS step, including the wait before the confirm, which since v0.10.0 is paid once per switch per apply, not once per step; see [`eos_config`](/modules/eos_config).

## Example usage

```hcl
step "users" {
  eos_vlan {
    vlan_id = 10
    name    = "users"
  }
}
```

One step per VLAN, from a map:

```hcl
step "vlans" {
  for_each = { users = 10, voice = 20, iot = 30 }

  eos_vlan {
    vlan_id = item.value
    name    = item.key
  }
}
```

## From Ansible

`conn3x convert ansible` turns `arista.eos.eos_vlans` tasks into an `eos_vlan` step per VLAN in `config`, with `vlan_id` and `name`. `state: merged`, the default, and `replaced` convert. `overridden` and `deleted` remove VLANs the play doesn't name, so they stay TODOs. Under `merged`, a VLAN without `name` also stays a TODO: Ansible leaves the name the switch has, while this step without `name` takes it back to the default. Set `name`, or use `replaced`, which resets it too. A VLAN with `state: suspend` stays a TODO, and so does one this step would refuse, with the step's own message.
