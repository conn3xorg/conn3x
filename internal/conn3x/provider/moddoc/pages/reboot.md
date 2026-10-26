Use `reboot` to restart a host and wait for it to come back before the next step runs. A `reboot` step reboots once, when it's created, and again whenever its `triggers` change. It doesn't reboot on every apply.

## Example usage

Reboot once, the first time the circuit is applied:

```hcl
step "reboot" {
  reboot {}
}
```

Reboot again whenever a value you choose changes, and allow a slow host more time to come back:

```hcl
step "reboot_for_kernel" {
  reboot {
    triggers = { kernel = "6.12.0-55" }
    timeout  = "20m"
  }
}
```
<!-- reference -->
## How it works

**Rebooting.** Conn3x reads the host's boot ID from `/proc/sys/kernel/random/boot_id`, then schedules `systemctl reboot` two seconds later, falling back to `reboot`, so the command returns before the connection drops.

**Waiting.** Every five seconds, Conn3x reconnects and reads the boot ID again. Once it has changed, the host has rebooted, the step records the new ID in `boot_id`, and the next step runs. If the host doesn't come back within `timeout`, which defaults to `"10m"`, the step fails. `timeout` takes a duration such as `"90s"` or `"20m"`.

**Triggers.** `triggers` is a map of strings. Any change to it reboots the host again, so tie it to what needs a reboot, such as a kernel version.

**Reading.** A `reboot` step has nothing on the host to drift, so plans don't connect to check it.

## Removal

Deleting a `reboot` step does nothing on the host.

## From Ansible

`conn3x convert ansible` leaves `reboot` tasks as TODOs. Ansible reboots on every play, while a Conn3x `reboot` step reboots once and again when its triggers change, so you choose the triggers.
