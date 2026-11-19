Use `mount` to mount a file system and keep it in `/etc/fstab`, so it's mounted again after a reboot. Each step is one mount point.

## Example usage

Mount a disk by its file system label:

```hcl
step "data" {
  mount {
    path   = "/srv/data"
    src    = "LABEL=data"
    fstype = "xfs"
    passno = 2
  }
}
```

Mount an NFS export with options:

```hcl
step "shared" {
  mount {
    path   = "/mnt/shared"
    src    = "nfs.example.com:/export/shared"
    fstype = "nfs4"
    opts   = "rw,noatime,_netdev"
  }
}
```

Mount a size-limited tmpfs:

```hcl
step "scratch" {
  mount {
    path   = "/scratch"
    src    = "tmpfs"
    fstype = "tmpfs"
    opts   = "size=512m,mode=1777"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the `/etc/fstab` entry for `path` and asks `findmnt` what's mounted there. `in_sync` is true when the entry matches, the file system is mounted, and its type is `fstype`. The mounted source is compared with `src` too, except for `UUID=` and `LABEL=` sources, which show as their device once mounted.

**The fstab entry.** Conn3x writes `<src> <path> <fstype> <opts> <dump> <passno>`, replacing any existing entry for the same mount point, and leaves the rest of the file alone. The last two fields are dump(8)'s frequency and fsck's pass, both `0` unless you set them, which is what Conn3x wrote before they were arguments. `passno = 2` has fsck check the file system at boot, after the root file system; `dump = 1` has dump(8) back it up, on hosts that run dump at all. Where systemd runs, Conn3x then runs `systemctl daemon-reload`, so systemd picks up the change.

**Mounting.** Conn3x creates the mount point if it's missing, then mounts it. Directly in a directory anyone can create in, such as `/tmp`, the mount point has to be one Conn3x creates or one root already owns. If the right file system is already mounted, it remounts it to apply new options. If a different file system is mounted there, Conn3x unmounts it and mounts the new one.

**Rules.** `path` must be an absolute path other than `/`. `path`, `src`, `fstype` and `opts` can't contain spaces. `dump` is `0` or `1`, and `passno` is `0`, `1` or `2`.

**Changes.** Changing `src`, `fstype`, `opts`, `dump` or `passno` updates the entry, and a change to the mount itself remounts it. An entry whose pass number on the host differs from `passno` counts as out of sync. Changing `path` replaces the step, and `on_remove` decides what happens to the old mount point.

## Removal

When you delete a `mount` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file system mounted and its entry in `/etc/fstab`. `"delete"` unmounts it and removes the entry.

## From Ansible

`conn3x convert ansible` turns `ansible.posix.mount` tasks with `state: mounted` into `mount` steps, taking the mount point from `path` or `name`, and `dump` and `passno` when the task sets them. A task with any other `state`, or with an argument such as `boot` or `backup`, stays a TODO.
