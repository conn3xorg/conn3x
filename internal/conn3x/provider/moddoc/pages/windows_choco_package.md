Use `windows_choco_package` to keep a Chocolatey package installed, at an exact version if you give one, or removed, on a Windows host that already has Chocolatey.

A Chocolatey package isn't checked the way `windows_package` checks an MSI. Its version comes from the feed, and its install script runs whatever the package says, as an administrator. Use a feed you control, give an exact `version`, and prefer `windows_package` with a `sha256` where there's an MSI.

## Example usage

```hcl
step "git" {
  windows_choco_package {
    name    = "git"
    version = "2.44.0"
    source  = "https://nuget.example.com/chocolatey/"
    pinned  = true
  }
}
```

```hcl
step "no_7zip" {
  windows_choco_package {
    name  = "7zip"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**Reading.** A plan runs nothing on the host. It finds Chocolatey from the machine's `ChocolateyInstall` variable and reads the package's files: the version from `lib\<name>\<name>.nuspec`, read with a parser that refuses a DTD and fetches nothing, and the pin from the `.pin` file Chocolatey keeps under `.chocolatey\<name>.<version>`. It refuses to read through a link in `lib`, `.chocolatey` or the package's folders. Of the package's folder in `.chocolatey`, only `.pin` is read: `.arguments` beside it holds the arguments it was installed with.

Package IDs ignore case, so `git` matches a package installed as `Git`. Versions compare as NuGet versions, so `version = "1.2"` matches `1.2.0`.

**Applying.** Apply runs `choco.exe` from Chocolatey's folder, with each value as its own argument. A missing package, or one at another version, is installed with `choco upgrade --version <version> --allow-downgrade`, which installs, upgrades or downgrades to exactly that version. Without a `version`, an installed package is left at whatever version it has, and a missing one gets the feed's newest. Chocolatey neither upgrades nor removes a pinned package, and reports success all the same, so the pin is taken off first: before an upgrade it's put back after, unless `pinned = false`. With `pinned` unset, the pin is left as it was.

**Rebooting.** It never reboots. `reboot_required` is true when `choco` exited 3010 or 1641, which it passes on from the package's installer whether or not enhanced exit codes are on. Follow it with `windows_reboot` and `only_if_pending`.

**Dependencies.** Packages a package depends on are installed by Chocolatey, but not managed by this step. Removing the package leaves them installed. Give each one a step of its own to manage it.

**Feeds.** `source` is an https feed URL or an absolute folder. Plain http is refused: a package's install script runs as an administrator, so anyone on the way to the feed could swap the package. A URL with a login in it is refused too, since it would be stored in state and shown in plans. Feed logins aren't supported yet. Without `source`, Chocolatey uses its configured sources: the community feed, unless the host's configuration says otherwise.

**Chocolatey itself.** This step doesn't install Chocolatey, which would mean running a script from the internet as an administrator. To install it from a file you've checked, download a pinned `chocolatey.<version>.nupkg` with `windows_download` and its `sha256`, then install it with a `windows_powershell` step.

**Not yet:** `install_args`, `override_args` and `package_params`, which reach the package's install script as free text, pre-releases, and `--force` reinstalls.

## Removal

Deleting a `windows_choco_package` step leaves the package as it is. To remove it, set `state = "absent"` and apply before deleting the step.
