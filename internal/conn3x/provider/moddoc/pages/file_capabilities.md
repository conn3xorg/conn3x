Use `file_capabilities` to give a program one privilege instead of root: `cap_net_bind_service` so a service binds port 443 as an ordinary user, `cap_net_raw` so `ping` works without setuid. It keeps a file's capabilities with `getcap` and `setcap`. It's `community.general.capabilities`, but it owns the file's whole set.

## Example usage

Let nginx bind ports below 1024 without starting as root:

```hcl
step "nginx_low_ports" {
  file_capabilities {
    path         = "/usr/sbin/nginx"
    capabilities = ["cap_net_bind_service+ep"]
  }
}
```
<!-- reference -->
## How it works

**Owned whole.** The file ends up with exactly `capabilities`. One it has that isn't listed is taken off. Write each the way `setcap` takes it, as `cap_net_raw+ep` or `cap_net_bind_service,cap_net_raw=ep`. They're compared by what they grant, so `cap_net_raw+ep` matches `cap_net_raw=ep`, which newer `getcap` prints.

**The effective flag.** The kernel keeps one `e` bit for the whole file, so every capability has `e` or none does. A mix is refused before anything reaches the host. So is `e` without `p` or `i`, which grants nothing, and `setcap` stores nothing for it.

**Drift.** A package upgrade that replaces the file drops its capabilities. The next plan shows the step out of sync and sets them again.

**The tools.** `getcap` and `setcap` come from `libcap2-bin` on Debian and Ubuntu, and from `libcap` on the Red Hat family. When they're missing, the step says which package to add. Put a `package` step before it.

## Removal

`on_remove = "forget"`, the default, leaves the capabilities. `on_remove = "delete"` takes them all off with `setcap -r`.

## From Ansible

`conn3x convert ansible` turns a `capabilities` task with `state: present` into a `file_capabilities` step with that one capability, and a TODO to add any others the file needs, since the step owns the whole set where Ansible adds one. It stays a TODO with `state: absent`, a capability taken off with `-`, a loop, or when more than one `capabilities` task in the play sets the same path: write one step listing them all.
