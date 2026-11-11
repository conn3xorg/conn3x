**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_feature` to install or remove a Windows Server role or feature. It never reboots a host. When Windows wants one, `reboot_required` says so, and a [`windows_reboot`](windows_reboot.md) step does it, so the reboot shows in the plan.

## Example usage

```hcl
step "iis" {
  windows_feature {
    name                     = "Web-Server"
    include_management_tools = true
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

```hcl
step "no_smb1" {
  windows_feature {
    name  = "FS-SMB1"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

Features install one at a time per host. An install can take several minutes, and `timeout` defaults to `"30m"`.

Windows Server only: Windows client has no such feature list. An `InstallPending` feature counts as installed, and shows `reboot_required`.

**The first plan after a big apply can be slow.** For ten minutes or so after a host's last reboot, a domain join or a promotion, Windows servicing is busy, and a feature read that normally takes a second can take a minute or more. On twenty Windows Server 2025 hosts, one plan straight after a 400-step apply spent 24 minutes of read time on features; the same plan run again straight after spent 5, with no apply in between. It's the host, not the read: wait a few minutes and plan again.

## Removal

Deleting a `windows_feature` step leaves the feature as it is. Use `state = "absent"` to remove one.
