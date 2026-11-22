**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI.

Use `junos_interface` to own a few settings on one interface of a Juniper Junos device: its description, whether it's enabled, its MTU, and on an ELS switch port, whether it's an access port or a trunk and which VLANs it carries. On an irb, a loopback or a routed port it can also own the addresses of one unit. Every setting you leave unset is left alone, and so is everything else under the interface. The change goes in like every Junos step does, once per device per circuit; see [`junos_config`](/modules/junos_config).

`enabled = false` is refused on a management interface (`fxp0`, `em0`, `me0`, `vme`), and on the interface whose address Conn3x connects to, since that would cut Conn3x off. `commit confirmed` would undo it, but only after five minutes.

`addresses` is one unit's whole set, IPv4 under `family inet` and IPv6 under `family inet6`. `unit` picks the unit, 0 when unset, so `irb.10` is `name = "irb"` with `unit = 10`. Addresses are compared as addresses, so case and zero compression don't matter, and new ones are set before old ones are deleted. Taking off the address Conn3x connects to is refused. `addresses` can't be combined with `mode`, `access_vlan` or `allowed_vlans`, and those need unit 0. Addresses are tested against parsed configurations only so far, not yet on vJunos-switch.

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

A gateway on `irb.10`:

```hcl
step "gateway" {
  junos_interface {
    name      = "irb"
    unit      = 10
    addresses = ["192.0.2.1/24", "2001:db8:10::1/64"]
  }
}
```

## From Ansible

`conn3x convert ansible` turns `junipernetworks.junos.junos_interfaces` tasks into a `junos_interface` step per interface in `config`, with `name`, `description`, `mtu` and `enabled`. Ansible defaults `enabled` to true, so a task without it converts with `enabled = true`. Only `state: merged`, the default, converts, and any other setting stays a TODO.

`junipernetworks.junos.junos_l3_interfaces` tasks become `junos_interface` steps with `unit` and `addresses`, IPv4 and IPv6 together. Only `state: replaced` converts, since `merged` adds to a set the step owns whole, so that task stays a TODO asking for every address. A `dhcp` address stays a TODO too.
