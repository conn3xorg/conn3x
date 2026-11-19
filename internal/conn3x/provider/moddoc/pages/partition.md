Use `partition` to give a new data disk its partition table and partitions, ready for [`filesystem`](/modules/filesystem) or [`lvm_volume_group`](/modules/lvm_volume_group). It's the `parted` you'd otherwise script, made safe to run on every apply: it makes what's missing, grows a partition when you ask, and refuses everything that could lose data.

## Example usage

A whole new disk as one partition for LVM:

```hcl
step "parted" {
  package {
    name = "parted"
  }
}

step "data_part" {
  partition {
    device = "/dev/vdb"
    number = 1
    start  = "1MiB"
    end    = "100%"
    flags  = ["lvm"]
  }
}
```

After the cloud provider enlarged the disk, let the partition follow:

```hcl
step "data_part" {
  partition {
    device = "/dev/vdb"
    number = 1
    start  = "1MiB"
    end    = "100%"
    flags  = ["lvm"]
    resize = true
  }
}
```

Use a stable name for the disk where you can, such as `/dev/disk/by-id/...`: `/dev/vdb` can be another disk after a reboot.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads the disk with `parted -m`. `in_sync` is true when the disk has the `label` table, and partition `number` runs from `start` to `end` with its `flags`. Start and end are compared within a MiB, since parted aligns them, and `100%` means the end of the disk, short of the backup GPT.

**A blank disk.** A disk with no partition table gets `label`, `gpt` unless you say `msdos`. Then the partition is made with `parted -a optimal`.

**What it refuses.** Each of these fails the step with nothing changed:
- relabelling a disk that has another partition table, which would lose every partition on it;
- shrinking a partition, which can lose what's past its new end;
- moving a partition's start;
- growing one without `resize = true`;
- a `number` that isn't the next free one, since parted numbers a new partition itself and would otherwise make a different one than you asked for.

**Flags.** `flags` is the partition's whole set: listed flags are set, and others are cleared. Leave it unset to leave them alone.

**Changes.** Changing `start`, `end`, `label` or `flags` updates the partition in place, within the limits above. Changing `device` or `number` replaces the step.

## Removal

A `partition` step has no `on_remove`, like the other storage steps. Taking it out of a circuit leaves the partition and its data as they are.

## From Ansible

`conn3x convert ansible` turns `community.general.parted` tasks with `state: present` into `partition` steps, with `device`, `number`, `part_start` as `start`, `part_end` as `end` (`100%` when unset, as in Ansible), `flags`, `resize` and `label`. Ansible's `label` defaults to `msdos`, and this step's to `gpt`, so a task without `label` gets `label = "msdos"`. A task stays a TODO, with the reason, when it sets no `part_start`, since Ansible's default of `0%` isn't a size this step takes, when its start or end isn't one this step takes, or when it sets `name`, `fs_type`, a `part_type` other than `primary` or an `align` other than `optimal`. `state: absent` and Ansible's default `state: info` stay TODOs too.
