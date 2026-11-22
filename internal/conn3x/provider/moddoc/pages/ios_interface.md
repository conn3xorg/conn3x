**Experimental.** Network devices are new, and this module may change between releases. It's tested against parsed running configurations only, not yet on a lab device, so try it on one first.

Use `ios_interface` to describe a port on a Cisco IOS XE device, bring it up or shut it down, make it an access port or a trunk, and set its MTU. Each setting you leave out is left alone, and so is every other line under the interface, such as its IP address. The change goes in like every IOS step does; see [`ios_config`](/modules/ios_config).

## Example usage

```hcl
step "uplink" {
  ios_interface {
    name          = "GigabitEthernet1/0/48"
    description   = "uplink to core"
    enabled       = true
    mode          = "trunk"
    allowed_vlans = [10, 20, 30]
  }
}
```

An access port in VLAN 10:

```hcl
step "desk" {
  ios_interface {
    name        = "GigabitEthernet1/0/5"
    mode        = "access"
    access_vlan = 10
  }
}
```
<!-- reference -->
## How it works

**Names.** Write the interface the way `show running-config` prints it, in full: `GigabitEthernet1/0/1`, not `Gi1/0/1`, and `Port-channel10` with a lowercase c. `mode`, `access_vlan` and `allowed_vlans` are for Ethernet ports and port channels; a `Vlan` or `Loopback` interface has no switchport.

**Trunks.** `allowed_vlans` is compared as a set. IOS prints a long list over several lines, the later ones starting `switchport trunk allowed vlan add`, and Conn3x reads them all, so `[30, 10, 20]` and a list IOS wrapped both read as in sync. A list that fits one command replaces the old one at once. A longer one goes as `switchport trunk allowed vlan add` lines for the VLANs that are missing, then `remove` lines for the ones that are going, at most 200 characters of VLANs each. IOS applies each line as it arrives, so a VLAN in both the old and the new list, the management VLAN included, never leaves the trunk while the change goes in. Some Catalyst images need `switchport trunk encapsulation dot1q` before a port can be a trunk; set that line with [`ios_config`](/modules/ios_config).

**The guard.** Shutting down the interface whose `ip address` is the one Conn3x connects to is refused before anything is sent. The revert timer would bring it back, but only after the full wait.

**Defaults.** `access_vlan = 1` is IOS's default, which `show running-config` leaves out, so Conn3x sends `no switchport access vlan` for it.

## Removal

By default, deleting an `ios_interface` step stops tracking it and leaves the port as it is. With `on_remove = "delete"`, Conn3x takes each setting it owns back to IOS's default with its `no` form, such as `no description` or `no switchport mode`. The interface itself stays. That includes `no shutdown`: a step with `enabled = false` and `on_remove = "delete"` brings the port back up when you delete it.

## From Ansible

`conn3x convert ansible` turns two cisco.ios modules into `ios_interface` steps, one per interface:

- **`cisco.ios.ios_interfaces`:** `description`, `enabled` and `mtu` carry over. `speed`, `duplex`, `mode` (`layer2` or `layer3`) and the other settings stay TODOs.
- **`cisco.ios.ios_l2_interfaces`:** `mode` (`access` or `trunk`), `access.vlan` and `trunk.allowed_vlans` carry over, with ranges such as `10-12` written out. `trunk.native_vlan`, `trunk.encapsulation`, a voice VLAN, the other modes and the other switchport settings stay TODOs.

For both modules, only `state: merged` converts. An interface's name must be the full one `show running-config` prints. Ansible expands a short name such as `Gi1/0/1` for you, but the converter leaves that task for review. A setting the step would refuse, such as a switchport on a `Vlan` interface, stays for review too, with the step's own message.
