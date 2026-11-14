**Experimental.** Network devices are new, and this module may change between releases. It's tested against VyOS rolling in a container on a lab VM, not yet in CI.

Use `vyos_static_route` to own one static route on a VyOS router: where traffic for a network goes, and at what distance. The step owns the route whole, so a next hop someone added by hand shows up as drift and goes on the next apply. The change goes in like every VyOS step does, once per router per circuit; see [`vyos_config`](/modules/vyos_config).

## Example usage

A route to a branch network over two links, preferred over a dynamic route:

```hcl
step "branch" {
  vyos_static_route {
    prefix    = "10.20.0.0/16"
    next_hops = ["192.0.2.1", "192.0.2.2"]
    distance  = 10
  }
}
```

An IPv6 route goes under `route6` on its own:

```hcl
step "branch_v6" {
  vyos_static_route {
    prefix    = "2001:db8:20::/48"
    next_hops = ["2001:db8::1"]
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the router's configuration with `show configuration commands`. `in_sync` is true when the route has exactly these next hops, each with `distance` when it's set, and nothing else under it.

**Applying.** Conn3x deletes whatever else is under the route, then sets what's missing, as `set protocols static route PREFIX next-hop ADDRESS`, with `distance N` when you set one. A next hop that isn't listed goes whole: on VyOS, deleting only its distance would leave the hop routing traffic. An IPv6 prefix goes under `route6`.

**Checks.** `prefix` must be a network, so `10.20.0.1/16` is refused with the network it meant, `10.20.0.0/16`. Every next hop must be an address of the prefix's family. `distance` is 1 to 255. VyOS uses 1 when it's unset, and 255 disables the route.

**Changes.** Changing `next_hops` or `distance` updates the route in place. Changing `prefix` replaces the step, and the old route is handled by its `on_remove`.

## Removal

`on_remove = "forget"`, the default, leaves the route on the router. `on_remove = "delete"` deletes the route and everything under it. When it was the router's last static route, VyOS keeps an empty `protocols static`, which does nothing.
