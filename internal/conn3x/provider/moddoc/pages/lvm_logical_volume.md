Use `lvm_logical_volume` to make a logical volume in a volume group, and to grow it. Each step is one volume, at `/dev/<vg>/<name>`, ready for a [filesystem](/modules/filesystem) step. The host needs the LVM tools.

## Example usage

A 20 GiB volume for an app, with a file system that grows with it:

```hcl
step "app_lv" {
  lvm_logical_volume {
    vg   = "vg0"
    name = "app"
    size = "20g"
  }
}

step "app_fs" {
  filesystem {
    device = "/dev/vg0/app"
    type   = "xfs"
    resize = true
  }
}
```

Give a volume whatever space the group has left when it's made:

```hcl
step "logs_lv" {
  lvm_logical_volume {
    vg   = "vg0"
    name = "logs"
    size = "100%FREE"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks LVM for the volume's size and the group's extent size. `in_sync` is true when the volume exists at its size, rounded up to whole extents, as LVM rounds it.

**Sizes.** `size` is one of:

- An amount: `512m`, `20g`, `1.5t`, in binary units, so `1g` is 1 GiB. A bare number is MiB, as for `lvcreate -L`.
- A share of the group, such as `50%VG`. Conn3x keeps the volume at that share of the group's size.
- A share of the group's free space, such as `100%FREE`. It sizes the volume only when it's made, since the free space shrinks once it is. After that, the volume is in sync at whatever size it has.

**Making and growing it.** If the volume doesn't exist, Conn3x runs `lvcreate`, wiping any stale signature in the new space. If it's smaller than `size`, Conn3x runs `lvextend`. Grow the file system on it with a `filesystem` step that sets `resize = true`.

**What it won't shrink.** A volume bigger than `size` stops the apply, unless `force = true`. Then Conn3x runs `lvreduce`, which destroys whatever is past the new end, and shrinks no file system first. With `force` on, every plan warns that the step can destroy data.

**Rules.** `vg` and `name` are LVM names: letters, digits and `_ . + -`, not starting with `-`. A percentage is from 1 to 100.

**Changes.** Changing `size` grows the volume, or shrinks it with `force`. Changing `vg` or `name` replaces the step.

## Removal

When you delete a `lvm_logical_volume` step, the volume stays on the host, with its data. There's no `on_remove`.

## From Ansible

`conn3x convert ansible` turns `community.general.lvol` tasks with `state: present` into `lvm_logical_volume` steps, with `lv` as `name`. `force` carries over, with a TODO to take it off. `resizefs` leaves a TODO to add a `filesystem` step with `resize = true`. A size relative to the current one, such as `+100%FREE`, or a share of `%PVS`, stays a TODO, as do snapshots and thin pools.
