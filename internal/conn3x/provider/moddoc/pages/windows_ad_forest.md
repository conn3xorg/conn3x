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

**Reads change nothing.** A refresh reads the host's domain role and the root domain from the registry. It doesn't load the AD tools, so a host without AD DS reads as having no forest rather than failing.

**The safe mode password.** `safe_mode_password_wo` goes to the host on stdin and becomes a `SecureString` through .NET before `Install-ADDSForest` sees it, so a logging policy that records cmdlet parameters records only the type name. It's never in plan or state, and it's blanked from errors. It's used once, when the forest is made: changing it later does nothing. To change the Directory Services Restore Mode password, use `ntdsutil` on the host.

**Settings used once.** `netbios_name`, `database_path`, `log_path` and `sysvol_path` apply only when the forest is made. Changing `domain_name` plans a new forest, which fails: Conn3x won't demote the host to make another.

**Logging in afterwards.** A domain controller has no local accounts. The admin you logged in as becomes the domain's account of the same name, and on Azure, where that admin is the built-in Administrator, it's in Domain Admins. Keep `ssh.user` as the bare name, such as `azadmin`, or the domain form, such as `LAB\azadmin`. A login named after the host, such as `win1\azadmin`, stops working, so Conn3x refuses to promote with one.

**What it refuses.** A host already in a domain, as a member or as a domain controller in another forest.

## Removal

Deleting a `windows_ad_forest` step leaves the forest and the domain controller as they are. Conn3x never demotes a domain controller. Delete the VM, or run `Uninstall-ADDSDomainController` yourself.
