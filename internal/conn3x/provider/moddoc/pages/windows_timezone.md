Use `windows_timezone` to set a Windows host's time zone. Use one per host.

## Example usage

```hcl
step "time_zone" {
  windows_timezone {
    name = "W. Europe Standard Time"
  }
}
```

```hcl
step "utc" {
  windows_timezone {
    name = "UTC"
  }
}
```
<!-- reference -->
## How it works

`name` is a Windows time zone ID, as `Get-TimeZone -ListAvailable` lists it, such as `Mountain Standard Time` or `Tokyo Standard Time`. It isn't an IANA name such as `America/Denver`: Windows' own table is what it takes, and the [`timezone`](/modules/timezone) step is for Linux hosts. Case doesn't matter, as it doesn't to Windows.

**Reading.** On every plan, Conn3x reads the zone with `Get-TimeZone`. `in_sync` is true when its ID is `name`. A `name` the host doesn't list fails the plan and names the three closest IDs it does, so a typo such as `Mountian Standard Time` points at `Mountain Standard Time`.

**Applying.** Conn3x runs `Set-TimeZone -Id`, then reads the zone back and fails if it isn't `name`. The change takes effect at once, with no reboot. Windows keeps the ID in the case you give it, which doesn't matter to it or to Conn3x. On GitHub's Windows Server 2022 and 2025 runners, each new SSH session took about 20 seconds to start after a time zone change, instead of well under a second. Once it lasted the rest of the job, even after the zone was put back. Once it passed after a minute. So steps after this one on a host can be slower. A reboot, which a time zone change doesn't need, is the sure way back.

## Removal

Deleting a `windows_timezone` step leaves the time zone as it is.

## From Ansible

`conn3x convert ansible` turns `community.windows.win_timezone` tasks into `windows_timezone` steps, with `timezone` as `name`. A zone ending in `_dstoff`, which turns daylight saving off, stays a TODO, since `windows_timezone` doesn't do that yet.
