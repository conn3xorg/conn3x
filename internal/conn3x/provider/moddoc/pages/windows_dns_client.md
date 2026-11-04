**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_dns_client` to point a Windows host at the DNS servers it should ask, such as a domain controller before the host joins its domain.

## Example usage

```hcl
step "dns_on_the_dc" {
  windows_dns_client {
    servers = ["10.0.0.4"]
  }
}
```

```hcl
step "dns_two_servers" {
  windows_dns_client {
    interface = "Ethernet 2"
    servers   = ["10.0.0.4", "10.0.0.5"]
  }
}
```
<!-- reference -->
## How it works

With no `interface`, Conn3x uses the interface that holds the IPv4 default route, the one with the lowest route and interface metric, as Windows chooses. On a tie it takes the lowest interface index. That matters on Azure: with accelerated networking a VM shows two adapters that are up, and only one of them carries DNS settings.

Order counts, so a list in a different order is drift. Unspecified, broadcast and multicast addresses are refused. Only the address families you list are managed. Give IPv4 servers alone, and the IPv6 ones stay as Windows has them.

The servers take effect at once, without a reboot. On Azure, pointing the guest at a domain controller this way doesn't disturb the Azure agent. Setting the virtual network's DNS servers instead also works, but a running VM picks them up only after `ipconfig /renew` or a reboot.

## Removal

Deleting a `windows_dns_client` step leaves the servers as they are.
