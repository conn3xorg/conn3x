Use `modprobe` to load a kernel module, such as `br_netfilter` for Kubernetes or `wireguard`, and keep it loaded after a reboot. Each step is one module.

## Example usage

Load `br_netfilter` and `overlay`, now and at every boot:

```hcl
step "kernel_modules" {
  for_each = ["br_netfilter", "overlay"]
  modprobe {
    name = item.value
  }
}
```

Load `nf_conntrack` with a bigger hash table:

```hcl
step "conntrack" {
  modprobe {
    name   = "nf_conntrack"
    params = ["hashsize=262144"]
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x checks `/proc/modules` for the module and reads each of `params` from `/sys/module/<name>/parameters`. With `persistent`, it reads the boot files too. `in_sync` is true when the module is loaded, or not, as `state` says, with its parameters and boot files. Module names compare as the kernel compares them, with `-` and `_` the same.

**Parameters.** A parameter the module shows in `/sys/module` is compared with its live value, and a bool shown as `Y` or `N` matches `1` or `0`. A module can also declare a parameter it doesn't show there. That one can't be read back, so with `persistent`, the options file stands in for it. Changing parameters unloads the module and loads it again, which fails while something is using it.

**Boot files.** With `persistent`, the default, Conn3x writes `/etc/modules-load.d/<name>.conf`, which loads the module at boot, and with `params`, `/etc/modprobe.d/<name>.conf`, which holds them. With `state = "absent"`, it removes both. `persistent = false` leaves those files as they are.

**Rules.** `name` is letters, digits, `_` and `-`. Each entry in `params` is `key=value`. A module that's absent takes no `params`.

**Changes.** Changing `params` or `state` loads, reloads or unloads the module. Changing `name` replaces the step, and `on_remove` decides what happens to the old module.

**Containers.** A container can't load a module into its host's kernel, so on a container host, apply fails at `modprobe`.

## Removal

When you delete a `modprobe` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the module loaded and its boot files in place. `"delete"` unloads it and removes its boot files.

## From Ansible

`conn3x convert ansible` turns `community.general.modprobe` tasks into `modprobe` steps, splitting `params` into words. Ansible's `persistent` defaults to `disabled`, which leaves the boot files alone, so a task that doesn't set it gets `persistent = false`. `persistent: present` with `state: present`, and `persistent: absent` with `state: absent`, map to the default. Any other mix stays a TODO.
