**Experimental.** Network devices are new, and this module may change between releases. It's tested against VyOS 2026.11.13-0016-rolling in a container on a lab VM, not yet in CI.

Use `vyos_interface` to own a few settings on one VyOS interface: its description, its addresses, whether it's enabled, and its MTU. Every setting you leave unset is left alone, and so is everything else under the interface. The change goes in like every VyOS step does, once per router per circuit; see [`vyos_config`](/modules/vyos_config).

`addresses` is the interface's whole set: an address that isn't listed is deleted. Two guards keep Conn3x from cutting itself off. It won't take off the address it connects to, and it won't disable the interface that holds it.

## Example usage

```hcl
step "lan" {
  vyos_interface {
    name        = "eth1"
    description = "lan"
    addresses   = ["192.168.10.1/24"]
    mtu         = 1500
  }
}
```
