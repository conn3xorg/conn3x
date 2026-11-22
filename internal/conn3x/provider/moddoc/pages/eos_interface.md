**Experimental.** Network devices are new, and this module may change between releases. It's tested against cEOS-lab 4.37.0F on a local machine, not yet in CI, so try it on a lab switch first.

Use `eos_interface` to own the everyday settings of one interface on an Arista EOS switch: its description, whether it's up, access or trunk, its VLANs, its MTU and, on a routed port, an SVI or a loopback, its addresses. Each setting you leave out is left alone, and so is every other line under the interface, such as a load interval. The change goes through the same config session as every other `eos_*` step on the switch: committed with a revert timer, confirmed over a new login, then saved.

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
A gateway address on an SVI:

```hcl
step "gateway" {
  eos_interface {
    name      = "Vlan10"
    addresses = ["192.0.2.1/24", "2001:db8:10::1/64"]
  }
}
```
<!-- reference -->
## How it works

Conn3x compares the lines under `interface <name>` in running-config with what the step owns. EOS doesn't print its defaults: an access port shows no `switchport mode` line, and access VLAN 1 shows none either. So `mode = "access"` takes a `switchport mode trunk` line away, and `access_vlan = 1` takes a `switchport access vlan` line away.

A setting the step stops naming is left as it is. Turn a trunk into an access port and its `switchport trunk allowed vlan` list stays on the switch, unused, until something removes it.

Shutting down the interface whose address Conn3x connects to is refused before anything is sent: `enabled = false` on that interface fails with the reason. Through any other interface, a lockout is still caught by the revert timer.

**Addresses.** `addresses` is the interface's whole set. The first IPv4 address is `ip address`, the rest are `ip address … secondary`, and IPv6 ones are `ipv6 address`. Addresses are compared as addresses, not as text, so `2001:DB8::1/64` matches `2001:db8::1/64`. New addresses go in before old ones come out, and taking off the address Conn3x connects to is refused. An Ethernet or Port-Channel interface is a switched port until it has `no switchport`, and a switched port can't take an address. So the step refuses until that line is there. Conn3x doesn't add it for you, since it takes the port out of its VLANs; set it with an [`eos_config`](/modules/eos_config) step before this one. `addresses` can't be combined with `mode`, `access_vlan` or `allowed_vlans`. Addresses are tested against parsed configurations only so far, not yet on cEOS-lab.

## Removal

With `on_remove = "forget"` (the default), removing the step leaves the interface as it is. With `"delete"`, the settings the step owns go back to EOS's defaults; the interface itself stays.

## From Ansible

`conn3x convert ansible` turns `arista.eos.eos_interfaces` tasks into an `eos_interface` step per interface in `config`, with `name`, `description`, `mtu` and `enabled`. Only `state: merged`, the default, converts. Any other setting, such as `speed` or `mode`, stays a TODO, since Ansible's `mode` is layer 2 or 3, not this step's access or trunk.
