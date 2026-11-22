**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI.

Use `junos_vlan` to create a VLAN on a Juniper EX or QFX switch running ELS, and give it an ID. Junos keys VLANs by name, so the name is what the step owns, and changing `vlan_id` updates it in place. Only the ID is owned: interfaces and a description you add elsewhere are left alone. Removing the step deletes the VLAN, everything under it included, unless `on_remove = "forget"`. The change goes in like every Junos step does; see [`junos_config`](/modules/junos_config).

## Example usage

```hcl
step "users" {
  junos_vlan {
    name    = "users"
    vlan_id = 10
  }
}
```

One step per VLAN, from a map:

```hcl
step "vlans" {
  for_each = { users = 10, voice = 20, iot = 30 }

  junos_vlan {
    name    = item.key
    vlan_id = item.value
  }
}
```

## From Ansible

`conn3x convert ansible` turns `junipernetworks.junos.junos_vlans` tasks into a `junos_vlan` step per VLAN in `config`, with `name` and `vlan_id`, both needed. Only `state: merged`, the default, converts. A VLAN with `l3_interface` stays a TODO.
