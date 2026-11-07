**Experimental.** Network devices are new, this module may change between releases, and it hasn't yet run against a switch in our CI.

Use `eos_vlan` to create a VLAN on an Arista EOS switch and give it a name. Removing the step deletes the VLAN, unless `on_remove = "forget"`. The change goes through a config session with a revert timer, like every EOS step; see [`eos_config`](/modules/eos_config).

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
