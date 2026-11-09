**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_ad_group` to keep a group in Active Directory, and to make sure the right accounts are in it. Run it on a domain controller.

## Example usage

```hcl
step "app_admins" {
  windows_ad_group {
    name        = "AppAdmins"
    path        = "OU=Lab,DC=lab,DC=example,DC=com"
    scope       = "global"
    description = "Can manage the app"
    members     = ["alice", "ops"]
  }
}
```

Accounts from another domain in the forest, or one it trusts, by `DOMAIN\name` or UPN. A universal or domain local group can hold them; a global group holds only its own domain's:

```hcl
step "forest_ops" {
  windows_ad_group {
    name    = "ForestOps"
    scope   = "universal"
    members = ["alice", "EMEA\\carol", "dave@apac.lab.example.com"]
  }
}
```

With `authoritative`, the list is the whole group:

```hcl
step "web_servers" {
  windows_ad_group {
    name          = "WebServers"
    members       = ["web1$", "web2$"]
    authoritative = true
  }
}
```
<!-- reference -->
## How it works

**Names.** `name` is the group's name and its sAMAccountName, the name you'd type after `LAB\`. The group is found by that name anywhere in the domain, so if it's sitting in another OU and `path` is set, apply moves it.

**Waiting for AD.** Straight after a DC reboots, Active Directory can answer for the domain a minute before its global catalog does, and a write made in that minute can hang. So apply first waits until a query through the global catalog works too, for up to 10 minutes, then fails with the reason AD last gave. A write that gets no answer at all runs once more when AD answers again. It reads first, so it only writes what's still missing. A host that isn't a DC isn't waited on.

**Members.** A bare name is a sAMAccountName in the group's own domain: `alice` for a user, `ops` for a group, `web1$` for a computer. An account in another domain takes its domain, as `EMEA\carol`, with the NetBIOS or DNS name, or as a UPN, `carol@emea.lab.example.com`. Not a distinguished name. Conn3x compares members by SID, so moving a user to another OU doesn't make the group drift, and one account written two ways is one member: listing `EMEA\carol` and `carol@emea.lab.example.com` together adds it once, and switching from one to the other changes the step's config but nothing in AD.

**Other domains.** The domain controller looks a name with a domain up as Windows does at logon, so an account in another domain of the forest, or in a domain the forest trusts, resolves, and its distinguished name comes from the global catalog. Members are added by SID, which reaches those domains. Seen on Azure, with a forest root and a child domain on Windows Server 2025: a child-domain user in a universal and a domain local group of the root, written both ways, removed by hand and put back, and a root account added by hand taken out by `authoritative`, each with a clean plan after. An account in a domain outside the forest, across a forest trust, is kept by AD as a foreign security principal, which Conn3x matches and names by SID. That path hasn't been tested yet.

By default, `members` are added and nobody else is taken out. With `authoritative = true` the list is complete, and anyone else is removed on apply, from any domain. Changes are written a thousand members at a time, so an apply that fails partway through a big change leaves the first batches done, and the next apply finishes the rest.

A member that doesn't exist yet, such as a user a later step makes, shows the group out of sync rather than failing the plan. At apply, a name that still doesn't resolve is an error, `no account named EMEA\nobody in the domain or a domain it trusts`, and nothing in the group changes. So put the users first, or chain the steps.

**Lockout guard.** Conn3x won't take its own login out of a group it gets its rights through, such as Domain Admins, so apply fails until the list keeps it.

**Scope and category.** Leave them unset and a new group is a global security group, as Windows makes one. A scope change between `global` and `domainlocal` goes through `universal`, because AD allows no direct step. AD refuses some changes anyway, such as making a domain local group that holds another domain local group global: the apply fails with AD's "A universal group cannot have a local group as a member", and the group keeps its scope. Changes both ways between `global` and `domainlocal`, and between `security` and `distribution`, were tested on a Windows Server 2025 domain controller, each with a clean second plan.

**Big groups.** A group with 5,001 members applied, with `authoritative = true`, and planned clean in about 20 seconds on a 2-vCPU domain controller. Members already in the group are found with one query, so a large group costs about as much to read as a small one.

**Drift.** A refresh reads the scope, category, description, location and members. A member added or removed by hand in Active Directory Users and Computers, or with `Add-ADGroupMember`, puts the step out of sync, and `conn3x drift` exits 2. Without `authoritative`, an extra member isn't drift. The plan names them: `pending_changes` lists each member the apply would add (`add CN=bob,...`) or take out (`remove CN=extra,...`), and each listed name the directory doesn't have (`not found ghost`), up to 50 and then a count. `conn3x drift` lists the group as changed, and `conn3x plan` shows that list.

## Removal

By default, deleting a `windows_ad_group` step leaves the group and its members. With `on_remove = "delete"` it deletes the group, unless the login Conn3x uses gets its rights through it.
