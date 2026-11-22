**Experimental.** Network devices are new, and this module may change between releases. It's tested against parsed running configurations only, not yet on a lab device, so try it on one first.

Use `ios_static_route` to own one static route on a Cisco IOS XE device: its next hops, and the distance they share. The change goes in like every IOS step does: under a revert timer, then a confirm over a new login. See [`ios_config`](/modules/ios_config).

## Example usage

A default route through two gateways:

```hcl
step "default" {
  ios_static_route {
    prefix    = "0.0.0.0/0"
    next_hops = ["192.0.2.1", "192.0.2.2"]
  }
}
```

A floating route that only takes over when a better one goes away:

```hcl
step "backup" {
  ios_static_route {
    prefix    = "10.20.0.0/16"
    next_hops = ["198.51.100.1"]
    distance  = 200
  }
}
```
<!-- reference -->
## How it works

**Owned whole.** The route's next hops are exactly `next_hops`. Any other line for the same prefix, such as a second gateway or `Null0`, is removed. Routes in a VRF (`ip route vrf …`) are separate, and left alone.

**The order of a change.** IOS applies each line as it arrives, so new next hops go in first, and the old ones come out after. A next hop in both the old and the new list stays put, and the prefix always has a route while the change goes in.

**How it's written.** Write `prefix` as a network with its length. IPv4 routes go to the device with a dotted mask, as `show running-config` prints them, so `10.20.0.0/16` becomes `ip route 10.20.0.0 255.255.0.0 …`. IPv6 routes use `ipv6 route`.

**Options on a line.** Options after the distance, such as `name` or `tag`, are left on the line. They don't make it out of sync.

**Matching.** Lines are compared on what they mean, not how they're written. IOS prints IPv6 addresses in upper case, as in `ipv6 route 2001:DB8:20::/48 2001:DB8::1`, and that matches `2001:db8:20::/48`.

**The management route.** Nothing stops a change to the route Conn3x itself reaches the device by, usually `0.0.0.0/0` on a management network. Adding before removing makes losing it unlikely, and if it happens, the revert timer brings the old route back. That takes the full wait, though, so test a change to that route on a lab device first.

## Removal

By default, deleting an `ios_static_route` step stops tracking the route and leaves it on the device. With `on_remove = "delete"`, Conn3x removes every next hop of the route.

## From Ansible

`conn3x convert ansible` turns `cisco.ios.ios_static_routes` tasks into an `ios_static_route` step per destination, IPv4 or IPv6, with each next hop's `forward_router_address` in `next_hops`. `distance_metric` becomes `distance` when every next hop has the same one. Only `state: replaced` converts. In this module, `replaced` also removes the address family's other static routes, the ones the task doesn't name. The converted steps leave those routes alone, so the first one gets a TODO saying so. Add a step with `on_remove = "delete"` for each route that should still go. Under `merged`, the default, Ansible adds the next hops to the ones the route has, while this step's `next_hops` are all of them, so a converted task would drop the route's other next hops. That task stays a TODO asking for every next hop. A `vrf`, an `interface` next hop, unequal distances and a route this step would refuse stay TODOs too.
