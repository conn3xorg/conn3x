Use `filesystem` to put a file system on a disk or a logical volume before you mount it, and to grow it when its device grows. Each step is one device.

## Example usage

Make an xfs file system on a new disk, then mount it:

```hcl
step "data_fs" {
  filesystem {
    device = "/dev/sdb"
    type   = "xfs"
  }
}

step "data" {
  mount {
    path   = "/srv/data"
    src    = "/dev/sdb"
    fstype = "xfs"
  }
}
```

Label an ext4 file system on a logical volume, and grow it whenever the volume grows:

```hcl
step "app_fs" {
  filesystem {
    device = "/dev/vg0/app"
    type   = "ext4"
    opts   = ["-L", "app"]
    resize = true
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks `blkid` what the device holds, and with `resize` how big the device and its file system are. `in_sync` is true when the device holds a file system of `type`, and with `resize`, when that file system fills the device to within 32 MiB.

**Making it.** On a device that holds nothing, Conn3x runs `mkfs` for `type`, with `opts` if you set them. `opts` are used only then: changing them later doesn't make the file system again.

**What it won't erase.** If the device holds anything else, another file system or an LVM physical volume, the apply stops and says what's there. It makes the new file system over it only with `force = true`, and never over one that's mounted. With `force` on, every plan warns that the step can destroy data. Take it off once the change is applied.

**Growing.** With `resize = true`, Conn3x grows the file system when its device is bigger: `resize2fs` for ext2, ext3 and ext4, running `e2fsck` first when it isn't mounted, and `xfs_growfs` for xfs, which grows only while mounted. It never shrinks a file system.

**Rules.** `device` must be a path under `/dev`. `type` is one of `btrfs`, `ext2`, `ext3`, `ext4`, `swap`, `vfat` and `xfs`. `resize` works for ext2, ext3, ext4 and xfs. Each entry in `opts` is one word.

**Changes.** Changing `type` makes the new file system, which needs `force`, since the device already holds the old one. Changing `device` replaces the step.

## Removal

When you delete a `filesystem` step, the device keeps its file system. There's no `on_remove`: erasing a file system is never something a removed step should do.
