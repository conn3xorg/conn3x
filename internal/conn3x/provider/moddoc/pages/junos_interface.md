**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI.

Use `junos_interface` to own a few settings on one interface of a Juniper Junos device: its description, whether it's enabled, its MTU, and on an ELS switch port, whether it's an access port or a trunk and which VLANs it carries. Every setting you leave unset is left alone, and so is everything else under the interface, its addresses included. The change goes in like every Junos step does, once per device per circuit; see [`junos_config`](/modules/junos_config).

`enabled = false` is refused on a management interface (`fxp0`, `em0`, `me0`, `vme`), and on the interface whose address Conn3x connects to, since that would cut Conn3x off. `commit confirmed` would undo it, but only after five minutes.

## Example usage

An access port:

```hcl
step "desk" {
  junos_interface {
    name        = "ge-0/0/5"
    description = "desk 12"
    mode        = "access"
    access_vlan = "users"
  }
}
```

A trunk to the next switch. VLANs not listed are taken off it:

```hcl
step "uplink" {
  junos_interface {
    name          = "ae0"
    description   = "to core"
    mode          = "trunk"
    allowed_vlans = ["users", "voice", "100-110"]
    mtu           = 9216
  }
}
```
