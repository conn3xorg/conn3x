**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_reboot` when a change needs a restart before the next step can run. No other Windows module reboots a host by itself, so reboots always show in the plan.

## Example usage

Reboot whenever a value changes:

```hcl
step "restart" {
  windows_reboot {
    triggers = { feature = "web-server" }
    timeout  = "15m"
  }
}
```

Reboot only when Windows is waiting for one:

```hcl
step "restart_if_needed" {
  windows_reboot {
    only_if_pending = true
  }
}
```
<!-- reference -->
## How it works

**Rebooting.** Conn3x reads the boot ID from the registry, runs `shutdown.exe /r /t 5`, reconnects, and finishes once the boot ID has changed. It fails if that takes longer than `timeout`, which defaults to `"10m"`. A plain reboot comes back in about 25 seconds, a domain controller in about 75.

**`only_if_pending`.** A refresh checks the markers Windows leaves when it wants a restart: component servicing, Windows Update, pending file renames and a changed computer name. If it finds one, the plan shows a reboot, so one that a failed run missed still happens.

**Other circuits wait.** Circuits run side by side, and a reboot would cut a session another circuit has open on the same host. So while a `windows_reboot` runs, from the moment it starts to the moment the host is back, no other Windows step reaches that host in the same run; they wait their turn, and the reboot waits for any already running. Hosts are told apart by address and port, so the same host reached by two different names isn't covered.

**Up is not ready.** sshd answers before everything else has started. Follow a reboot with [`windows_wait_for`](windows_wait_for.md) on whatever the next step needs.

## Removal

Deleting a `windows_reboot` step does nothing on the host.
