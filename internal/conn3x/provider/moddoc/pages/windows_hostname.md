Use `windows_hostname` to rename a Windows host that isn't in a domain. Use one per host. Linux hosts use [`hostname`](/modules/hostname).

## Example usage

A rename, and a reboot only when one is waiting:

```hcl
step "name" {
  windows_hostname {
    name = "WEB01"
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

`name` is the computer name alone, without a domain: 15 characters at most, letters, digits and hyphens, not starting or ending with a hyphen, and not all digits, so that it works as both the NetBIOS and the DNS host name. Case doesn't matter, as it doesn't to Windows.

**Reading.** On every plan, Conn3x reads the name the host is running under and the one it will have after a reboot, from `ActiveComputerName` and `ComputerName` under `HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName`. `in_sync` is true when the name for the next boot is `name`, so the plan after a rename is clean even before the reboot. `reboot_required` is true while the two differ.

**Applying.** Conn3x runs `Rename-Computer -NewName` without `-Restart`, then reads the name back. Asking for the name the host is running under, while another one waits for the reboot, undoes that rename: `Rename-Computer` refuses it as the name the host already has, so Conn3x renames through `Win32_ComputerSystem.Rename` instead, Windows' own rename, which sets everything for the next boot that a rename does.

**Reboots.** The step never reboots. The new name takes effect at the next one, which a [`windows_reboot`](/modules/windows_reboot) step with `only_if_pending = true` does when Windows has one pending.

**Domain members.** A host in a domain is refused, at apply, before anything changes. Renaming it renames its computer account in Active Directory too, which can need a domain account with the right to do that. Rename it before it joins the domain, with this step before a [`windows_domain_membership`](/modules/windows_domain_membership) step.

## Removal

Deleting a `windows_hostname` step leaves the name as it is.

## From Ansible

`conn3x convert ansible` turns `ansible.windows.win_hostname` tasks into `windows_hostname` steps, with `name` carried across. Ansible doesn't reboot either: its task result has `reboot_required`, and so does the step, so a play that reboots when it's set can use a `windows_reboot` step with `only_if_pending = true` instead. Ansible compares only the running name, so its next run before the reboot shows a change again, where Conn3x's plan is clean.
