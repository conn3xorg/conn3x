**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_ad_domain_controller` to add a domain controller to a domain that already exists. Two DCs mean the domain keeps answering when one is down. It never reboots the host, and promotion always needs a reboot, so follow it with a [`windows_reboot`](windows_reboot.md) step, then wait for AD to answer.

## Example usage

The host needs the AD DS role, and DNS that finds the domain.

```hcl
step "ad_ds" {
  windows_feature {
    name                     = "AD-Domain-Services"
    include_management_tools = true
  }
}
```

```hcl
step "dc" {
  windows_ad_domain_controller {
    domain_name           = "lab.example.com"
    username              = "LAB\\azadmin"
    password_wo           = "use an ephemeral variable here"
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
<!-- reference -->
## How it works

**Promotion.** Conn3x runs `Install-ADDSDomainController` with `-InstallDns` and `-NoRebootOnCompletion`, so the new DC is a DNS server and a global catalog, as Windows makes one by default. Two paths have been tested on Azure, each with a clean second plan: joining the host to the domain first with [`windows_domain_membership`](windows_domain_membership.md), then promoting it, and promoting a Windows Server 2025 host straight from a workgroup, with its DNS pointed at a domain controller by [`windows_dns_client`](windows_dns_client.md). On a 2-vCPU VM promotion takes about a minute.

**Why it needs a password.** A key login has no password to show the domain, so promotion uses the account in `username` and `password_wo`. It has to be able to add domain controllers: a member of Domain Admins can.

**The passwords.** `password_wo` and `safe_mode_password_wo` go to the host on stdin and become `SecureString` values through .NET before the cmdlet sees them, so a logging policy that records cmdlet parameters records only the type name. They're never in plan or state, and they're blanked from errors. Both are used once, at promotion. To change the Directory Services Restore Mode password later, use `ntdsutil` on the host.

**Reboots.** `reboot_required` is true after promotion, and promotion leaves the marker `windows_reboot` with `only_if_pending` looks for. sshd answers before AD does, which is why the example waits for Active Directory Web Services on port 9389.

**Reads change nothing.** A refresh reads the host's domain role, its domain and NTDS's root domain from the registry, and loads no AD tools. A host promoted but not yet rebooted counts as a DC while the reboot marker is there.

**Folders.** `database_path`, `log_path` and `sysvol_path` are checked as [`windows_ad_forest`](windows_ad_forest.md) checks them: a folder that exists must be empty, owned by an administrator, not a link, and writable by nobody else. A missing one is made with SYSTEM and Administrators only.

**Settings used once.** `username` and the folders apply only at promotion. Changing `domain_name` plans a new promotion, which fails: Conn3x won't demote the host.

**Logging in afterwards.** A domain controller has no local accounts. Seen on Azure, the bare name, such as `azadmin`, logs in as the domain's account of that name after promotion, with the domain's password for it and the same key. A local login, such as `win2\azadmin` or `.\azadmin`, stops working, so Conn3x refuses to promote with one.

**What it refuses.** A host that's a domain controller already, in any domain, and a host that's a member of another domain.

## Removal

Deleting a `windows_ad_domain_controller` step leaves the domain controller as it is. Conn3x never demotes one. Delete the VM, or run `Uninstall-ADDSDomainController` yourself.
