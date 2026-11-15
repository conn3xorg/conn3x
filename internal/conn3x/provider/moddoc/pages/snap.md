Use `snap` for what Ubuntu ships as snaps: `lxd`, `microk8s`, `certbot`, `code`. It installs a snap that's missing, moves one onto the channel you name, and tells you on every plan whether the host still matches, which a `command` step running `snap install` can't.

## Example usage

Install LXD:

```hcl
step "lxd" {
  snap {
    name = "lxd"
  }
}
```

Keep MicroK8s on a release track, so a refresh never jumps a minor version:

```hcl
step "microk8s" {
  snap {
    name    = "microk8s"
    channel = "1.28/stable"
    classic = true
  }
}
```

Take a snap off a host, and remove it again if the step goes:

```hcl
step "no-chromium" {
  snap {
    name      = "chromium"
    state     = "absent"
    on_remove = "delete"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `snap list name` and reads the Tracking and Notes columns. `in_sync` is true when the snap is installed, tracks `channel` when one is set, and is classic when `classic` is true. With `state = "absent"`, it's true when the snap isn't there. snapd prints no machine-readable listing, so Conn3x asks for plain text with `--unicode=never --color=never` and reads the columns, which never hold spaces.

**Channels.** A channel is `track/risk`, with an optional `/branch`. `stable` means `latest/stable`, and a track alone, such as `5.21`, means `5.21/stable`, the same as `snap install` reads them. Without `channel`, a snap that's already installed keeps whatever it tracks, and a new one gets the store's default.

**Applying.** A missing snap is installed with `snap install`, with `--channel` and `--classic` as set. An installed one that tracks another channel, or needs classic confinement, is moved with `snap refresh --channel`. A snap that's already classic stays classic when `classic` is false, since snapd has no refresh back to strict confinement; remove it first if that's what you need. snap exits 0 on a refresh that changed nothing, so Conn3x reads the host back and fails the step if it still differs.

**Without snapd.** A host with no `snap` command fails the step with an error that names the `snapd` package to install. A host where snapd is installed but not running fails with snap's own message.

**Changes.** Changing `channel`, `classic` or `state` updates the snap in place. Changing `name` replaces the step, and the old snap is handled by its `on_remove`.

## Removal

`on_remove = "forget"`, the default, leaves the snap installed. `on_remove = "delete"` runs `snap remove name`, which keeps snapd's snapshot of its data, as `snap remove` does by hand.

## From Ansible

`conn3x convert ansible` turns `community.general.snap` tasks with `state: present` or `absent` into `snap` steps, keeping `name`, `channel` and `classic`. `state: enabled` and `disabled`, `options` and `dangerous` stay for review, since the step has no equivalent.
