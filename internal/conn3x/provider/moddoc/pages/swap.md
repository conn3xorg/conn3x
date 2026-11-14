Use `swap` to give a host swap space and keep it on across reboots. On a 1 GB VM that's the difference between a slow build and the OOM killer taking your database, and doing it by hand is a `fallocate`, a `chmod`, `mkswap`, `swapon` and an `/etc/fstab` line you hope you typed right.

## Example usage

A 2 GB swap file:

```hcl
step "swap" {
  swap {
    path = "/swapfile"
    size = "2G"
  }
}
```

A disk that's already formatted as swap, used before any other swap:

```hcl
step "swap_disk" {
  swap {
    path     = "/dev/disk/by-uuid/0b9d5f1e-4c1a-4f6e-9d1e-2a7f3c5b8e10"
    priority = 10
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the swap's entry in `/etc/fstab`, whether `/proc/swaps` lists it and at what priority, and, with `size`, the file's size. `in_sync` is true when all of them match.

**A swap file.** With `size`, Conn3x makes the file with `fallocate`, or `dd` where `fallocate` can't, gives it mode `0600` and owner root, and runs `mkswap`. When `size` changes, it turns the swap off, makes the file again at the new size, and turns it back on. The file's directory must not be one anyone can write to, such as `/tmp`.

**A device.** Without `size`, `path` must already be swap. Conn3x never runs `mkswap` on a device or on a file it didn't make, since that wipes what's there, so the step fails and says so. Run `mkswap` yourself, once, if the disk is new.

**Turning it on.** Conn3x runs `swapon`, with `-p` for `priority`, and writes `path none swap defaults 0 0`, or `pri=N` in place of `defaults`, to `/etc/fstab`. A change of `priority` turns the swap off and on again.

**Changes.** Changing `size` or `priority` updates the swap in place. Changing `path` replaces the step, and the old swap is handled by its `on_remove`.

## Removal

`on_remove = "forget"`, the default, leaves the swap on and in `/etc/fstab`. `on_remove = "delete"` turns it off, removes its `/etc/fstab` entry and, for a swap file made with `size`, deletes the file.
