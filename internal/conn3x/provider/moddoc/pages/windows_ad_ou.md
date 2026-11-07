**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_ad_ou` to keep an organizational unit in Active Directory. Run it on a domain controller: that's where your SSH login is a domain account.

## Example usage

```hcl
step "lab_ou" {
  windows_ad_ou {
    name        = "Lab"
    description = "Made by Conn3x"
  }
}
```

An OU inside another one names its parent in `path`:

```hcl
step "servers_ou" {
  windows_ad_ou {
    name = "Servers"
    path = "OU=Lab,DC=lab,DC=example,DC=com"
  }
}
```
<!-- reference -->
## How it works

**Where it runs.** On a domain controller, after the reboot that finishes its promotion, and after AD answers: follow [`windows_ad_forest`](windows_ad_forest.md) with a reboot and a wait on port 9389. On a member server with the AD tools installed it would still fail, because a key login there has no domain credentials to reach AD with.

**Finding it.** The OU is looked up by `name` directly under `path`, or under the top of the domain when `path` is unset. So changing either plans a new OU, and the old one is forgotten, not moved.

**Protection.** Windows protects a new OU from accidental deletion, and so does Conn3x unless you set `protected = false`. Leave `protected` unset to keep whatever the OU has.

**Drift.** A refresh reads the description and the protection flag. If someone changes either in Active Directory Users and Computers, the next plan shows the step out of sync, and `conn3x drift` exits 2.

**Reads change nothing.** A refresh only runs `Get-ADObject` and `Get-ADOrganizationalUnit`. A host without the ActiveDirectory module reads as having no OU, rather than failing.

## Removal

By default, deleting a `windows_ad_ou` step leaves the OU and everything in it. With `on_remove = "delete"` Conn3x deletes it, but only when it's empty and not protected: it never deletes what's inside an OU. Set `protected = false` and apply first, then remove the step.
