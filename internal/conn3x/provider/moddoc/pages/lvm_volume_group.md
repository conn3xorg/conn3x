Use `lvm_volume_group` to gather disks into an LVM volume group, which [lvm_logical_volume](/modules/lvm_logical_volume) steps then carve up. Each step is one group. The host needs the LVM tools: a `package` step for `lvm2` before this one.

## Example usage

Make `vg0` from two disks:

```hcl
step "lvm2" {
  package {
    name = "lvm2"
  }
}

step "vg0" {
  lvm_volume_group {
    name = "vg0"
    pvs  = ["/dev/sdb", "/dev/sdc"]
  }
}
```

Add a third disk later by adding it to `pvs`. Conn3x extends the group.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks LVM whether the group exists and which physical volumes are in it. Each device in `pvs` is compared by what it resolves to, so `/dev/disk/by-id/...` matches the `/dev/sdb` LVM reports. `in_sync` is true when the group exists with every device in `pvs`.

**Making and extending it.** If the group doesn't exist, Conn3x runs `vgcreate` with `pvs`. If it exists, Conn3x runs `vgextend` with the devices it's missing. A device that isn't a physical volume yet becomes one.

**What it won't erase.** A device that holds a file system stops the apply, unless `force = true`, which erases it. A device in another volume group, or one that's mounted, always stops it. With `force` on, every plan warns that the step can destroy data.

**What it leaves.** A physical volume in the group but not in `pvs` stays in it. Taking one out means moving its data off first, which is a call for you, with `pvmove` and `vgreduce`.

**Rules.** `name` is an LVM name: letters, digits and `_ . + -`, not starting with `-`. Each device in `pvs` is a path under `/dev`.

**Changes.** Adding a device to `pvs` extends the group. Changing `name` replaces the step.

## Removal

When you delete a `lvm_volume_group` step, the group stays on the host, with its volumes and their data. There's no `on_remove`.
