**Experimental.** Network devices are new, and this module may change between releases. It's tested against parsed running configurations only, not yet on cEOS-lab, so try it on a lab switch first.

Use `eos_static_route` to own one static route on an Arista EOS switch: its next hops, and the distance they share. The change goes through a config session with a revert timer, like every EOS step. See [`eos_config`](/modules/eos_config).

## Example usage

```hcl
step "default" {
  eos_static_route {
    prefix    = "0.0.0.0/0"
    next_hops = ["192.0.2.1", "192.0.2.2"]
  }
}
```
<!-- reference -->
## How it works

**Owned whole.** The route's next hops are exactly `next_hops`. Any other line for the same prefix, such as a second gateway or `Null0`, is removed. Routes in a VRF (`ip route vrf …`) are separate, and left alone.

**How it's written.** Conn3x writes `ip route 10.20.0.0/16 …`, the way EOS prints it, and reads a line written with a dotted mask too. IPv6 routes use `ipv6 route`. Lines are compared on what they mean, not how they're written, so case and zero compression in an IPv6 address don't matter.

**The order of a change.** New next hops go in first, and old ones come out after, so a next hop in both lists stays put.

**The management route.** Nothing stops a change to the route Conn3x reaches the switch by. If that change cuts Conn3x off, the revert timer brings the old route back, but only after the full wait.

## Removal

By default, deleting an `eos_static_route` step stops tracking the route and leaves it on the switch. With `on_remove = "delete"`, Conn3x removes every next hop of the route.
