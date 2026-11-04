**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_ad_forest` to make a new Active Directory forest, with this host as its first domain controller and DNS server. It never reboots the host. Promotion always needs a reboot, so follow it with a [`windows_reboot`](windows_reboot.md) step, then wait for AD to answer before anything uses it.

## Example usage

```hcl
step "ad_ds" {
  windows_feature {
    name                     = "AD-Domain-Services"
    include_management_tools = true
  }
}
```

```hcl
step "forest" {
  windows_ad_forest {
    domain_name           = "lab.example.com"
    netbios_name          = "LAB"
    safe_mode_password_wo = "use an ephemeral variable here"
  }
}
```

```hcl
step "promoted" {
  windows_reboot {
    only_if_pending = true
    timeout         = "15m"
  }
}
```

```hcl
step "adws" {
  windows_wait_for {
    port    = 9389
    timeout = "10m"
  }
}
```

```hcl
step "ad_answers" {
  windows_powershell {
    script = <<-PS
      $deadline = (Get-Date).AddMinutes(5)
      while ($true) {
        try { Import-Module ActiveDirectory; Get-ADDomain | Out-Null; break }
        catch { if ((Get-Date) -gt $deadline) { throw } ; Start-Sleep -Seconds 5 }
      }
    PS
    unless = "Import-Module ActiveDirectory; Get-ADDomain | Out-Null"
  }
}
```
<!-- reference -->
## How it works

**Promotion.** Conn3x runs `Install-ADDSForest` with `-InstallDns` and `-NoRebootOnCompletion`. The AD DS role must already be there, with its management tools: add a `windows_feature` step for `AD-Domain-Services` first. On a 2-vCPU VM promotion takes about a minute, and the reboot after it about 75 seconds. sshd answers before AD does, which is why the example waits for Active Directory Web Services on port 9389 and then for `Get-ADDomain`.

**Reboots.** `reboot_required` is true after promotion. Promotion also leaves the same marker `windows_package` uses, so `windows_reboot` with `only_if_pending` reboots after it, and a run that stopped before the reboot plans it next time.

**Reads change nothing.** A refresh reads the host's domain role and the root domain from the registry. Before its reboot, a promoted host counts as this forest only while the reboot marker promotion left is there. It doesn't load the AD tools, so a host without AD DS reads as having no forest rather than failing. A domain controller reads as the forest its root domain names, so a DC of a child domain reads as its forest root. If the root domain value is missing, the read falls back to the domain Windows reports for the computer.

**The safe mode password.** `safe_mode_password_wo` goes to the host on stdin and becomes a `SecureString` through .NET before `Install-ADDSForest` sees it, so a logging policy that records cmdlet parameters records only the type name. It's never in plan or state, and it's blanked from errors. It's used once, when the forest is made: changing it later does nothing. To change the Directory Services Restore Mode password, use `ntdsutil` on the host.

**Folders.** On a new data volume, any user can make a folder at the top and own it, or make a junction to a folder they own. AD keeps its database and every domain controller's logon scripts in `database_path`, `log_path` and `sysvol_path`, so before promoting, Conn3x checks each one. A folder that exists must be empty, owned by an administrator, not be a link, and give nobody else write access, including through rules it hands down. The folders above it are checked for their owner and for who can rename or replace what's inside, and must not be links. A folder that doesn't exist yet is made with SYSTEM and Administrators only. Read access isn't checked: promotion replaces the rules on all three folders with its own protected ones. Seen on Server 2025, the database folder ends up with SYSTEM and Administrators only, and SYSVOL gives read to Authenticated Users and Server Operators, as Windows intends. Unset, the folders are Windows' defaults under `C:\Windows`, where only administrators can write. The top of the volume counts too: one formatted on Azure belonged to NETWORK SERVICE, so give it to Administrators first, as with `icacls F:\ /setowner *S-1-5-32-544` in the step that formats it.

**Settings used once.** `netbios_name`, `database_path`, `log_path` and `sysvol_path` apply only when the forest is made. Changing `domain_name` plans a new forest, which fails: Conn3x won't demote the host to make another.

**Logging in afterwards.** A domain controller has no local accounts. The admin you logged in as becomes the domain's account of the same name, and on Azure, where that admin is the built-in Administrator, it's in Domain Admins. Keep `ssh.user` as the bare name, such as `azadmin`, or the domain form, such as `LAB\azadmin`. A local login, such as `win1\azadmin` or `.\azadmin`, stops working, so Conn3x refuses to promote with one. Windows can pick a different NetBIOS name from the one you'd expect, so to use the `LAB\azadmin` form, set `netbios_name`.

**What it refuses.** A host already in a domain, as a member or as a domain controller in another forest.

## Removal

Deleting a `windows_ad_forest` step leaves the forest and the domain controller as they are. Conn3x never demotes a domain controller. Delete the VM, or run `Uninstall-ADDSDomainController` yourself.
