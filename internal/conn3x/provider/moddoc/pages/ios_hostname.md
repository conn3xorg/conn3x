**Experimental.** Network devices are new, and this module may change between releases. It's tested against a parsed running configuration only, not yet on a lab device, so try it on one first.

Use `ios_hostname` to name a Cisco IOS XE device. The change goes in like every IOS step does: under a revert timer, then a confirm over a new login and `write memory`, once per device per circuit. See [`ios_config`](/modules/ios_config), including the configuration archive it needs.

## Example usage

```hcl
step "name" {
  ios_hostname {
    name = each.key
  }
}
```
<!-- reference -->
## How it works

**Names.** IOS takes letters, digits and hyphens. A name starts with a letter, ends with a letter or digit, and runs to 63 characters at most, as Cisco's command reference sets out. An all-digit name is refused before anything reaches the device.

**In sync.** The step compares the top-level `hostname` line without regard to case, since Cisco doesn't promise to keep it. So a change of case alone isn't applied: with `Edge01` on the device, `name = "EDGE01"` is already in sync, and nothing is sent.

## Removal

When you delete an `ios_hostname` step, Conn3x stops tracking it. The device keeps its name; Conn3x never sends `no hostname`.

## From Ansible

`conn3x convert ansible` turns `cisco.ios.ios_hostname` tasks into `ios_hostname` steps, with `config.hostname` as `name`. `state: merged` and `replaced` convert; `deleted`, `overridden`, `gathered`, `rendered` and `parsed` stay TODOs. So does a name the step would refuse, with the step's own message, so it shows in the convert output instead of failing `conn3x validate` later.
