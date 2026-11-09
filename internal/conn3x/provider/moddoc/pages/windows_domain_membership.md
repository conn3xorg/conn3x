**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_domain_membership` to join a Windows server to an Active Directory domain. It never reboots the host. A join only takes effect after a reboot, so follow it with a [`windows_reboot`](windows_reboot.md) step.

## Example usage

The server has to find the domain first, so point its DNS at a domain controller.

```hcl
step "dns" {
  windows_dns_client {
    servers = ["10.44.0.4"]
  }
}
```

```hcl
step "join" {
  windows_domain_membership {
    domain      = "lab.example.com"
    username    = "LAB\\joiner"
    password_wo = "use an ephemeral variable here"
  }
}
```

```hcl
step "joined" {
  windows_reboot {
    only_if_pending = true
  }
}
```
<!-- reference -->
## How it works

**Why it needs a password.** Conn3x logs in with an SSH key, and a key login has no password of its own to show the domain. So the join runs `Add-Computer` with the account you give in `username` and `password_wo`. The account needs the right to join computers: a member of Domain Admins has it, or delegate it on an OU.

**The password.** `password_wo` goes to the host on stdin and becomes a `SecureString` through .NET before `Add-Computer` sees it, so a logging policy that records cmdlet parameters records only the type name. It's never in plan or state, and it's blanked from errors. It's used once, when the host joins. Changing it later does nothing, and Conn3x can't tell if it's still right.

**Reboots.** `reboot_required` is true after a join. The join also leaves the marker `windows_reboot` with `only_if_pending` looks for, so a run that stopped before its reboot plans the reboot next time.

**Reads change nothing.** A refresh reads whether the computer is in a domain, and which, from `Win32_ComputerSystem`. A host that joined but hasn't rebooted yet already reads as joined. A domain controller of the same domain counts as joined, so promoting a member later with [`windows_ad_domain_controller`](windows_ad_domain_controller.md) doesn't make this step plan again.

**The OU.** `ou` is the distinguished name of the OU the computer's account goes in, such as `OU=Servers,OU=Lab,DC=lab,DC=example,DC=com`. Unset, it goes in `CN=Computers`. Make the OU first, with a [`windows_ad_ou`](windows_ad_ou.md) step: a missing one fails the join before anything changes on the host, with an error naming the OU. Joining into an OU doesn't need rights on it as long as the domain's defaults stand: any domain user may add up to 10 computers anywhere, through the "Add workstations to domain" right and `ms-DS-MachineAccountQuota`. Where the quota is 0, an account without rights on the OU fails with AD's "You have exceeded the maximum number of computer accounts you are allowed to create in this domain".

**Joining again.** If the host leaves the domain behind Conn3x's back, the next plan joins it again. When the reboot step after it is already in state, it plans from what the refresh saw, before the join, so the reboot comes in the apply after: run `conn3x plan` again and it lists it.

**Tested.** On Azure, Windows Server 2022 Datacenter (Desktop Experience, build 20348.5773) joined a Windows Server 2025 domain into an OU, and the second plan was clean.

**Settings used once.** `ou` and `username` apply only when the host joins. Changing `domain` plans a new join, which fails: Conn3x won't take the host out of the domain it's in.

**Logging in afterwards.** Nothing changes for the SSH login. On a member server, the bare name, such as `azadmin`, is still the local account, and so is `win2\azadmin`. A domain account can log in too, once it's in the server's Administrators group and has the key.

**What it refuses.** A host already in another domain.

## Removal

Deleting a `windows_domain_membership` step leaves the host in the domain. Conn3x never takes a host out of one. Delete the VM, or run `Remove-Computer` yourself and then delete its computer account in the domain.
