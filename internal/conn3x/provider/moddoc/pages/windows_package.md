**Experimental.** Windows support is new, and this module may change between releases.

Use `windows_package` to install an MSI, or remove one, by its product code. Nothing installs unless the file matches the SHA-256 you give, and Conn3x never reboots on its own: when msiexec asks for a reboot, a `windows_reboot` step with `only_if_pending` does it.

## Example usage

```hcl
step "seven_zip" {
  windows_package {
    product_code = "{23170F69-40C1-2702-2409-000001000000}"
    url          = "https://github.com/ip7z/7zip/releases/download/24.09/7z2409-x64.msi"
    sha256       = "ec6af1ea0367d16dde6639a89a080a524cebc4d4bedfe00ed0cac4b865a918d8"
  }
}
```

```hcl
step "agent" {
  windows_package {
    product_code = "{11111111-2222-3333-4444-555555555555}"
    source       = "C:\\installers\\agent.msi"
    sha256       = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    properties   = { INSTALLDIR = "C:\\Program Files\\Agent" }
  }
}
```

```hcl
step "reboot_if_needed" {
  windows_reboot {
    only_if_pending = true
  }
}
```
<!-- reference -->
## How it works

**Checking the file.** The host downloads `url`, or copies `source`, into a folder only SYSTEM and Administrators can write to, under `C:\ProgramData\Conn3x`. Conn3x refuses that folder, or one on the way, if anyone else could rename or replace it, or if it's a link. It then opens the file so nothing can change or delete it, hashes it through that handle, and runs msiexec while still holding it. A file that doesn't match is deleted and nothing installs. The copy is deleted after msiexec finishes either way, and anything an interrupted run left there is cleared at the start of the next. Two runs applying packages to one host at the same moment can trip over that clean-up, and one may fail; run it again. The file that installs is still the one that was checked.

**Downloads.** `url` must be https; `allow_http = true` lets it be, or redirect to, plain http, since `sha256` still guards the file. Conn3x follows redirects itself, up to five, and refuses one from https to http unless that's allowed. A download bigger than `max_size_mb`, 2048 by default, stops.

**Installed or not.** Conn3x reads Windows' Uninstall entries for `product_code`, in both the 64-bit and 32-bit views. It never asks `Win32_Product`, which can start a repair of every MSI on the host. A new version of a package usually has a new product code, so it's a new step, and the old one is left for msiexec's upgrade to replace. Changing `url`, `sha256` or `properties` alone doesn't reinstall: a package that's installed is in sync.

**Properties.** `properties` go on msiexec's command line, quoted the way msiexec reads them, and into state. Never pass a secret here: process auditing records command lines. `ALLUSERS` is `1` unless you set it, since a per-user install lands in the login's profile, where Conn3x doesn't look. `TRANSFORMS`, `PATCH`, `MSIPATCHREMOVE`, `REBOOT`, `REMOVE`, `ACTION`, `REINSTALL`, `REINSTALLMODE`, `SOURCEDIR` and `SOURCELIST` are refused: a transform or patch isn't covered by `sha256` and can add actions that run as SYSTEM, and `REBOOT=Force` would override `/norestart`. `SOURCEDIR` and `SOURCELIST` would point later repairs, which run as SYSTEM, at files `sha256` never covered.

**Reboots.** msiexec runs with `/norestart`. Exit code 3010 or 1641 sets `reboot_required`, and records the need on the host in a registry key that the next boot clears. `windows_reboot` with `only_if_pending` checks that key, so a run that stops after the install and before the reboot step still plans the reboot next time. Exit code 1618 means another installation is running. `reboot_required` describes the last change: it stays true in state after the reboot, until the package changes again. Use `windows_reboot` with `only_if_pending` to act on it, not the attribute.

**No copy kept.** The .msi is deleted after installing. Windows keeps its own cached copy, but a repair or removal that needs the original source, as some packages do, has to be given it again.

## Removal

Deleting a `windows_package` step leaves the package installed. To remove it, set `state = "absent"`, which runs `msiexec /x` for the product code.
