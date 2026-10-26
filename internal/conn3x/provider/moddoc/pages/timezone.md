Use `timezone` to set a host's time zone by its IANA name, such as `Europe/Dublin` or `UTC`. A host has one time zone, so a circuit needs only one `timezone` step.

## Example usage

Run every host on UTC:

```hcl
step "utc" {
  timezone {
    name = "UTC"
  }
}
```

Set a regional zone:

```hcl
step "dublin" {
  timezone {
    name = "Europe/Dublin"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads where `/etc/localtime` points and takes the zone name after `zoneinfo/`. `in_sync` is true when that equals `name`.

**Applying.** Conn3x first checks that `/usr/share/zoneinfo/<name>` exists, and fails with a hint to install the `tzdata` package if it doesn't. It then runs `timedatectl set-timezone`. Where that fails, as in a container without systemd, it links `/etc/localtime` to the zone file itself. If `/etc/timezone` exists, as on Debian and Ubuntu, Conn3x writes the zone name there too.

**Reboots.** The zone lives in `/etc/localtime`, so it holds across reboots.

## Removal

A `timezone` step has no `on_remove`. When you delete it, Conn3x stops managing the time zone and leaves the host as it is.

## From Ansible

`conn3x convert ansible` turns `community.general.timezone` tasks into `timezone` steps. A task that sets `hwclock` stays a TODO.
