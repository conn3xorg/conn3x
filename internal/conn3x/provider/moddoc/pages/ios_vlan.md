**Experimental.** Network devices are new, and this module may change between releases. It's tested against parsed running configurations only, not yet on a lab switch, so try it on one first.

Use `ios_vlan` to create a VLAN on a Cisco IOS XE switch and name it. The change goes in like every IOS step does: under a revert timer, then a confirm over a new login. See [`ios_config`](/modules/ios_config).

The switch has to be in VTP transparent mode. Put the mode line first, and the VLANs after it:

```hcl
step "vtp" {
  ios_config {
    lines = ["vtp mode transparent"]
  }
}

step "users" {
  ios_vlan {
    vlan_id = 10
    name    = "users"
  }
}
```
<!-- reference -->
## How it works

**VTP transparent mode only.** In VTP server mode, a VLAN you create or delete goes to every switch in the VTP domain, and the VLANs live in `vlan.dat`, outside the running configuration the revert timer rolls back. A change made there can't be undone by the timer, and it doesn't stay on the switch you meant. In transparent mode, or `off` under VTP version 3, the switch keeps its VLANs to itself and in its running configuration. So before any change, `ios_vlan` looks for a `vtp mode transparent` or `vtp mode off` line, and refuses without one. A step earlier in the same circuit that sets the mode counts.

**Names.** `name` is one word of up to 32 printable ASCII characters, without `?`, which the IOS command line takes as a request for help. Leave it unset for the switch's default, such as `VLAN0010`, and a name set by hand is taken away with `no name`.

**Reserved VLANs.** VLAN 1 and VLANs 1002 to 1005 belong to IOS. They can't be renamed or deleted, so `ios_vlan` refuses them.

**In sync.** A VLAN with nothing set under it can show up in a list with others, as in `vlan 20,30-32`. That counts as the VLAN being there.

## Removal

By default, deleting an `ios_vlan` step deletes the VLAN with `no vlan`. Ports in it stop passing traffic until they're moved to another VLAN. Set `on_remove = "forget"` to stop tracking the VLAN and leave it on the switch.
