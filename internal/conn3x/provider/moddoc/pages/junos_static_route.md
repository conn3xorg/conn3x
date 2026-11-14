**Experimental.** Network devices are new, and this module may change between releases. It's tested against vJunos-switch 26.2R1.7 on a lab VM, not yet in CI.

Use `junos_static_route` to own one static route on a Juniper Junos device: its next hops, and its preference over other routes to the same network. The step owns the route whole, so a next hop or a `discard` someone added by hand shows up as drift and goes on the next apply. The change goes in like every Junos step does, once per device per circuit; see [`junos_config`](/modules/junos_config).

## Example usage

A route to a branch network over two links, preferred over the default for static routes:

```hcl
step "branch" {
  junos_static_route {
    prefix     = "10.20.0.0/16"
    next_hops  = ["192.0.2.1", "192.0.2.2"]
    preference = 10
  }
}
```

An IPv6 route goes in the `inet6.0` table on its own:

```hcl
step "branch_v6" {
  junos_static_route {
    prefix    = "2001:db8:20::/48"
    next_hops = ["2001:db8::1"]
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the device's configuration as `set` statements. `in_sync` is true when the route has exactly these next hops, `preference` when it's set, and nothing else under it.

**Applying.** Conn3x deletes whatever else is under the route, then sets what's missing, as `set routing-options static route PREFIX next-hop ADDRESS`. An IPv6 prefix goes under `routing-options rib inet6.0 static route`. A preference that's no longer wanted is deleted whole, since Junos refuses a commit that leaves an empty `preference` behind.

**Checks.** `prefix` must be a network. Junos would take `10.20.0.1/16` as a route of its own beside `10.20.0.0/16`, so the step refuses it and names the network it meant. Every next hop must be an address of the prefix's family. `preference` is 0 to 4294967295, and lower wins.

**Changes.** Changing `next_hops` or `preference` updates the route in place. Changing `prefix` replaces the step, and the old route is handled by its `on_remove`.

## Removal

`on_remove = "forget"`, the default, leaves the route on the device. `on_remove = "delete"` deletes the route and everything under it.
