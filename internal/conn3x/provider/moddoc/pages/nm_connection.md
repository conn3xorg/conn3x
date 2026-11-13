Use `nm_connection` to set up a network connection with NetworkManager: a static address, a bond, or a VLAN. Each step is one connection profile, which Conn3x writes as a keyfile and brings up. A change is guarded by default: if Conn3x can't log in again after it, the host puts the old profile back by itself.

## Example usage

A static address on a second interface:

```hcl
step "lan" {
  nm_connection {
    name   = "lan"
    type   = "ethernet"
    ifname = "eth1"
    ip4    = ["192.0.2.10/24"]
    gw4    = "192.0.2.1"
    dns4   = ["192.0.2.53"]
  }
}
```

A bond of two ports, with a VLAN on it:

```hcl
step "bond0" {
  nm_connection {
    name         = "bond0"
    type         = "bond"
    ifname       = "bond0"
    bond_mode    = "802.3ad"
    bond_options = { miimon = "100" }
    ip4          = ["disabled"]
    ip6          = ["disabled"]
  }
}

step "bond0_ports" {
  for_each = ["eth2", "eth3"]
  nm_connection {
    name       = "bond0-${item.value}"
    type       = "ethernet"
    ifname     = item.value
    controller = "bond0"
  }
}

step "vlan10" {
  nm_connection {
    name        = "vlan10"
    type        = "vlan"
    ifname      = "bond0.10"
    vlan_parent = "bond0"
    vlan_id     = 10
    ip4         = ["198.51.100.10/24"]
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the keyfile, `/etc/NetworkManager/system-connections/<name>.nmconnection`, and asks `nmcli` which connections are up. `in_sync` is true when the keyfile is exactly the one Conn3x writes and, with `autoconnect`, the connection is up. An edit with `nmcli connection modify`, which rewrites the keyfile, shows as a change.

**Applying.** Conn3x writes the whole keyfile, owned by root and readable by nobody else, as NetworkManager requires. Then it runs `nmcli connection reload` and, with `autoconnect`, `nmcli connection up`. The host's other profiles are left alone.

**The lockout guard.** Changing the connection Conn3x logs in over is the classic way to lose a server. So by default, before the change, the host keeps a copy of the old keyfile and schedules its own revert after `confirm_after`, 60 seconds unless you say otherwise. After the change, Conn3x logs in again over a new connection and cancels the revert. If that login doesn't come, the host puts the old keyfile back and reloads, whatever happened to Conn3x, and the apply fails. `confirm_after = "off"` turns the guard off. It needs systemd.

**Addresses.** `ip4` and `ip6` take addresses with their prefixes, or `["auto"]` (DHCP for IPv4, autoconfiguration for IPv6, the default for both) or `["disabled"]`. A bond port has no addresses of its own: set them on the bond.

**Rules.** `type` is `ethernet`, `bond` or `vlan`. `ifname` is 15 characters or fewer. Only an `ethernet` connection can be a bond port, through `controller`. `vlan_parent` and `vlan_id` are for a `vlan`, and `bond_mode` and `bond_options` for a `bond`. `mtu` is from 576 to 65535.

**Changes.** Changing any setting rewrites the keyfile and brings the connection up again, behind the guard. Changing `name` replaces the step, and `on_remove` decides what happens to the old profile.

## Removal

When you delete an `nm_connection` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the profile and the connection as they are. `"delete"` removes the profile with `nmcli connection delete`, which takes the connection down. Removal isn't guarded, so don't delete the connection Conn3x logs in over.
