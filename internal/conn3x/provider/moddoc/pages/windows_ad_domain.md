**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_ad_domain` to add a child domain to a forest that exists, with this host as the new domain's first domain controller and DNS server. Shops that split by region or business unit do this: `emea.lab.example.com` under `lab.example.com`. It never reboots the host. Promotion always needs a reboot, so follow it with a [`windows_reboot`](windows_reboot.md) step, then wait for AD to answer.

## Example usage

The host needs the AD DS role, and DNS that finds the parent domain. Point it at a domain controller of the parent with [`windows_dns_client`](windows_dns_client.md), with loopback second, which promotion adds anyway.

```hcl
step "ad_ds" {
  windows_feature {
    name                     = "AD-Domain-Services"
    include_management_tools = true
  }
}
```

```hcl
step "dns" {
  windows_dns_client {
    servers = ["10.46.0.4", "127.0.0.1"]
  }
}
```

```hcl
step "domain" {
  windows_ad_domain {
    domain_name           = "emea.lab.example.com"
    netbios_name          = "EMEA"
    username              = "azadmin@lab.example.com"
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

**Promotion.** Conn3x runs `Install-ADDSDomain` with `-DomainType ChildDomain`, `-InstallDns`, `-CreateDnsDelegation` and `-NoRebootOnCompletion`. `domain_name` is the new domain's full name, and everything after its first label is the parent, so `emea.lab.example.com` goes under `lab.example.com`. The parent's DNS gets a delegation to this server, so names in the new domain resolve from the rest of the forest. The new domain controller is a global catalog, as Windows makes one by default, and the new domain trusts its parent both ways, as every child domain does. On Azure, with two 2-vCPU Windows Server 2025 VMs, promotion took under 3 minutes, the reboot after it about 6, and the second plan made no change to either domain.

**Why it needs a password.** A key login has no password to show the forest, so promotion uses the account in `username` and `password_wo`. Adding a domain to a forest takes a member of Enterprise Admins, such as the forest root's first administrator. It belongs to the parent domain or one above it. Name it by that domain's DNS name, as `azadmin@lab.example.com` or `lab.example.com\azadmin`: the host isn't in the forest yet, so it finds the domain through DNS, and `Install-ADDSDomain` refuses `LAB\azadmin`. Conn3x checks this before anything reaches the host.

**The passwords.** `password_wo` and `safe_mode_password_wo` go to the host on stdin and become `SecureString` values through .NET before the cmdlet sees them, so a logging policy that records cmdlet parameters records only the type name. They're never in plan or state, and they're blanked from errors. Both are used once, at promotion. To change the Directory Services Restore Mode password later, use `ntdsutil` on the host.

**Reboots.** `reboot_required` is true after promotion, and promotion leaves the marker `windows_reboot` with `only_if_pending` looks for. sshd answers before AD does, which is why the example waits for Active Directory Web Services on port 9389. The AD steps that come after wait for the global catalog themselves.

**Reads change nothing.** A refresh reads the host's domain role, its domain and NTDS's root domain from the registry, and loads no AD tools. Until the reboot, Windows still says the host is in a workgroup, so promotion records the new domain's name in the reboot marker, which goes with the reboot. While it's there, a promoted host counts as a domain controller in that domain.

**Folders.** `database_path`, `log_path` and `sysvol_path` are checked as [`windows_ad_forest`](windows_ad_forest.md) checks them: a folder that exists must be empty, owned by an administrator, not a link, and writable by nobody else. A missing one is made with SYSTEM and Administrators only.

**Settings used once.** `netbios_name`, `username` and the folders apply only at promotion. Changing `domain_name` plans a new promotion, which fails: Conn3x won't demote the host.

**Logging in afterwards.** A domain controller has no local accounts. Seen on Azure, the bare name, such as `azadmin`, logs in as the new domain's account of that name after promotion, `EMEA\azadmin`, with the same key. A local login, such as `dc2\azadmin` or `.\azadmin`, stops working, so Conn3x refuses to promote with one. To use the domain form, set `netbios_name` so Conn3x can check it's the new domain's.

**What it refuses.** A host that's a domain controller already, and a host that's a member of a domain: promoting it would take it out, and Conn3x never does that. A `domain_name` with fewer than three labels, since a child needs a parent with two.

## Removal

Deleting a `windows_ad_domain` step leaves the domain and its domain controller as they are. Conn3x never demotes one. Delete the VM, or run `Uninstall-ADDSDomainController` yourself, which for the last domain controller of a domain also removes the domain from the forest.
