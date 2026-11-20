Use `windows_optional_feature` to turn a Windows optional feature on or off, such as the Telnet client, .NET Framework 3.5 or the Windows Subsystem for Linux. These are the features DISM lists, on desktop and server editions alike. Server roles and features, such as `Web-Server`, are [`windows_feature`](/modules/windows_feature).

## Example usage

```hcl
step "telnet" {
  windows_optional_feature {
    name = "TelnetClient"
  }
}
```

.NET 3.5 from install media, with a reboot only if Windows asks for one:

```hcl
step "netfx3" {
  windows_optional_feature {
    name           = "NetFx3"
    include_parent = true
    source         = "D:\\sources\\sxs"
  }
}
```

```hcl
step "restart_if_needed" {
  windows_reboot {
    only_if_pending = true
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the feature with `Get-WindowsOptionalFeature -Online`. With `state = "present"`, `in_sync` is true when it's `Enabled`, or `EnablePending`, waiting for a reboot. With `"absent"`, it's true when it's `Disabled`, `DisablePending` or `DisabledWithPayloadRemoved`. So a change waiting for a reboot plans clean the second time. A name Windows doesn't list fails the plan.

**Applying.** Conn3x runs `Enable-WindowsOptionalFeature`, with `-All` when `include_parent` is true and `-Source` when `source` is set, or `Disable-WindowsOptionalFeature`. It always passes `-NoRestart`, then reads the feature back. Windows servicing takes one change at a time, so Conn3x runs one `windows_feature` or `windows_optional_feature` change per host at a time. `timeout` defaults to `30m`.

**Reboots.** The step never reboots. `reboot_required` is true when Windows said the change needs one. A [`windows_reboot`](/modules/windows_reboot) step with `only_if_pending = true` after it reboots only then.

## Removal

Deleting a `windows_optional_feature` step leaves the feature as it is. To turn it off, set `state = "absent"`.

## From Ansible

`conn3x convert ansible` turns `ansible.windows.win_optional_feature` tasks into `windows_optional_feature` steps, a step for each `name` in the list. `state`, `include_parent` and `source` carry across. Ansible's task result has `reboot_required`, and so does the step, so a play that reboots when it's set can use a `windows_reboot` step with `only_if_pending = true` instead.
