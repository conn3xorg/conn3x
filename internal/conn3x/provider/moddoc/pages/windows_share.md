**Experimental.** New, and tested on GitHub's Windows Server 2022 and 2025 runners, not yet on an Azure server. See [Windows readiness](https://github.com/conn3xorg/conn3x/blob/main/docs/windows-readiness.md).

Use `windows_share` to keep an SMB share on a Windows file server, and who may use it, in a plan. It's `New-SmbShare` and a few `Grant-SmbShareAccess` calls you'd otherwise run by hand, with drift showing when someone clicks a permission in.

## Example usage

The folder first, then the share on it:

```hcl
step "finance_folder" {
  windows_directory {
    path = "D:\\Shares\\Finance"
  }
}

step "finance_share" {
  windows_share {
    name          = "Finance"
    path          = "D:\\Shares\\Finance"
    description   = "Finance team files"
    full_access   = ["BUILTIN\\Administrators"]
    change_access = ["CONTOSO\\Finance"]
    read_access   = ["CONTOSO\\Auditors"]
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the share with `Get-SmbShare` and its access list with `Get-SmbShareAccess`. Accounts compare by their SID, so `Administrators` and `BUILTIN\Administrators` are the same account. `in_sync` is true when the share is on `path`, has `description` when you set one, and its Allow entries are exactly the step's.

**Access.** Set any of `full_access`, `change_access` and `read_access`, and the three together are the share's whole set of Allow entries. Conn3x grants what's missing and revokes what isn't listed, in place, so the share never goes away while access changes. An account in two lists gets the stronger right. Deny entries are left as they are. Leave all three unset to leave access alone; a new share then has `New-SmbShare`'s own default, Read for Everyone.

**Share access, not folder access.** These are the share's permissions. A user needs both these and the folder's NTFS permissions, which [`windows_acl`](/modules/windows_acl) sets.

**Changes.** Changing `description` or an access list updates the share in place. Changing `name` or `path` replaces the step: a share's folder can't change in place.

**What's refused.** Windows' own administrative shares, such as `C$`, `ADMIN$` and `IPC$`, an account the host doesn't know, and a `path` that isn't a folder on the host.

## Removal

`on_remove = "delete"`, the default, removes the share when the step goes, as with every step that grants access. The folder and its files stay. `on_remove = "forget"` leaves the share.
