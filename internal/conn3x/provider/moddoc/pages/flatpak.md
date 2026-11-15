Use `flatpak` to put an app from Flathub, or any other Flatpak remote, on a desktop or kiosk, and to keep it there. Every plan reads `flatpak list`, so an app someone uninstalled by hand shows up in `conn3x drift`.

## Example usage

Install an app from Flathub for every user on the host:

```hcl
step "calculator" {
  flatpak {
    name = "org.gnome.Calculator"
  }
}
```

Install a few at once, into the connecting user's own installation:

```hcl
step "desktop_apps" {
  for_each = toset(["org.mozilla.firefox", "org.videolan.VLC", "org.libreoffice.LibreOffice"])
  flatpak {
    name   = item.value
    method = "user"
  }
}
```

Keep an app at the newest build the remote has, and take one out:

```hcl
step "browser" {
  flatpak {
    name  = "org.mozilla.firefox"
    state = "latest"
  }
}
```

```hcl
step "old_player" {
  flatpak {
    name  = "org.gnome.Totem"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**The remote.** `remote` is where a missing app is installed from, and defaults to `flathub`. The host has to have it already: Conn3x doesn't add remotes, so add Flathub with a `command` step guarded by `flatpak remotes`, or bake it into the image. An app that's already installed is accepted from whatever remote it came from, as Ansible's module does.

**Reading.** On every plan, Conn3x runs `flatpak list` for the installation `method` names. `in_sync` is true when the app is installed, or with `state = "absent"` when it isn't. With `state = "latest"` it also asks the remote with `flatpak remote-ls --updates`, which takes network access, and is out of sync while the remote has a newer build.

**Applying.** A missing app is installed with `flatpak install -y --noninteractive remote name`, and its runtime comes with it. An outdated one is updated with `flatpak update`. An unwanted one is uninstalled; its runtime stays, since other apps may share it. Nothing runs when the host already matches.

**The installation.** `method = "system"`, the default, is the installation every user on the host shares, and needs root. `method = "user"` is the connecting user's own installation under their home, and the remote has to be added there too, with `flatpak remote-add --user`.

**Changing a step.** Changing `remote` or `state` updates in place. Changing `name` or `method` replaces the step, and the old app is handled by its `on_remove`.

## Removal

When you delete a `flatpak` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the app installed. `"delete"` uninstalls it.

## From Ansible

`conn3x convert ansible` turns `community.general.flatpak` tasks into `flatpak` steps, one for each name, keeping `remote`, `method` and `state`. A task stays a TODO with the reason when a name is a ref such as `app/org.gnome.Calculator/x86_64/stable` or a URL to a `.flatpakref` file, when it sets `executable` to something other than `flatpak`, or when it sets `no_dependencies`, which the step doesn't have.
