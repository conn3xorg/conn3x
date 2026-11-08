**Experimental.** Network devices are new, and this module may change between releases. It's tested against cEOS-lab 4.37.0F on a local machine, not yet in CI, so try it on a lab switch first.

Use `eos_interface` to own the everyday settings of one interface on an Arista EOS switch: its description, whether it's up, access or trunk, its VLANs and its MTU. Each setting you leave out is left alone, and so is every other line under the interface, such as an IP address or a load interval. The change goes through the same config session as every other `eos_*` step on the switch: committed with a revert timer, confirmed over a new login, then saved.

## Example usage

An uplink trunk:

```hcl
step "uplink" {
  eos_interface {
    name          = "Ethernet1"
    description   = "to spine1"
    mode          = "trunk"
    allowed_vlans = [10, 20, 30]
    mtu           = 9214
  }
}
```

An access port for one VLAN:

```hcl
step "printer" {
  eos_interface {
    name        = "Ethernet12"
    description = "printer, 2nd floor"
    mode        = "access"
    access_vlan = 30
  }
}
```

Shut down ports nobody uses:

```hcl
step "unused" {
  for_each = toset(["Ethernet40", "Ethernet41", "Ethernet42"])
  eos_interface {
    name    = item.value
    enabled = false
  }
}
```
<!-- reference -->
## How it works

Conn3x compares the lines under `interface <name>` in running-config with what the step owns. EOS doesn't print its defaults: an access port shows no `switchport mode` line, and access VLAN 1 shows none either. So `mode = "access"` takes a `switchport mode trunk` line away, and `access_vlan = 1` takes a `switchport access vlan` line away.

A setting the step stops naming is left as it is. Turn a trunk into an access port and its `switchport trunk allowed vlan` list stays on the switch, unused, until something removes it.

Shutting down the interface whose address Conn3x connects to is refused before anything is sent: `enabled = false` on that interface fails with the reason. Through any other interface, a lockout is still caught by the revert timer.

## Removal

With `on_remove = "forget"` (the default), removing the step leaves the interface as it is. With `"delete"`, the settings the step owns go back to EOS's defaults; the interface itself stays.
