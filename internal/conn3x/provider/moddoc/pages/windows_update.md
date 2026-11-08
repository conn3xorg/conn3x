**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_update` to keep a Windows Server patched. Each refresh asks Windows Update what's waiting in the categories you name, and when anything is, the plan says which KBs it will install. Apply downloads and installs them, and a second plan says `No changes.` until next month's updates arrive.

It never reboots a host. When an update wants one, `reboot_required` says so, and a [`windows_reboot`](windows_reboot.md) step does it, so the reboot shows in the plan.

## Example usage

This month's security and critical updates, then a reboot only if one is due:

```hcl
step "patch" {
  windows_update {}
}
```

```hcl
step "reboot_after_patching" {
  windows_reboot {
    only_if_pending = true
  }
}
```

Defender definitions only, which install in a minute or two:

```hcl
step "definitions" {
  windows_update {
    categories = ["DefinitionUpdates"]
  }
}
```

Hold back one update you know breaks something:

```hcl
step "patch_but_not_that_one" {
  windows_update {
    reject_list = ["KB5034441"]
  }
}
```
<!-- reference -->
## How it works

Windows Update refuses to download or install for a remote login, so Conn3x registers a one-off scheduled task that runs as SYSTEM, waits for it, and removes it. The script it runs and its input and output sit in a new folder under `C:\Windows`, where only administrators can create anything, so nothing can be swapped in before SYSTEM runs it. Searching, which plan and drift need, runs over the SSH login as usual.

A big cumulative update can take a long time. `timeout` defaults to `"2h"`.

Updates install one change at a time per host, like features. If some install and others fail, the step fails, names the ones that didn't, and logs the ones that did.

Some updates only appear once others are in. Defender's platform update turned up right after its definitions on Windows Server 2025, for one. So apply searches again after each install, up to three rounds, and stops early when an update wants a reboot. Whatever is left then, the next plan after the reboot picks up.

## Removal

Removing the step installs and removes nothing.
