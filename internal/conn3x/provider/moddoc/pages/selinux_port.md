Use `selinux_port` to give a port an SELinux port type, so a service confined to that type may listen on it. Move PostgreSQL to 5433 or a web server to 8081 on an SELinux host and the service is refused the port until it has the right type. The rule applies on hosts with SELinux enabled, which in practice means the Red Hat family. On a host without SELinux the step reads in sync and does nothing, so one circuit can cover Debian and Rocky Linux alike.

## Example usage

Let the web server listen on 8081. `semanage` comes from the `policycoreutils-python-utils` package:

```hcl
step "semanage" {
  package {
    name = "policycoreutils-python-utils"
  }
}

step "http_alt" {
  selinux_port {
    port   = 8081
    setype = "http_port_t"
  }
}
```

A range of HTTPS ports for the web server:

```hcl
step "https_alt" {
  selinux_port {
    port   = "8443-8450"
    setype = "http_port_t"
  }
}
```

Set `protocol` to `"udp"`, `"dccp"` or `"sctp"` for anything other than TCP.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x lists the host's local port rules with `semanage port -l -C` and finds the one for `port` on `protocol`. `in_sync` is true when that rule gives `setype`. A range matches only the same range: `8443` isn't in sync because a rule covers `8443-8450`. On a host where `selinuxenabled` isn't installed or says SELinux is off, `in_sync` is true and nothing is read. That includes a container on an SELinux host, which sees the host's `/sys/fs/selinux` but can't change its policy. With SELinux enabled, the step fails if `semanage` isn't installed.

**Applying.** Conn3x adds the rule with `semanage port -a`. When the port is already defined, by the policy or by a local rule, `-a` fails and Conn3x changes it with `-m` instead. Only local rules are read, so the first plan shows a change even for a port the policy already gives `setype`.

**Reboots.** Rules live in the SELinux policy store, so they hold across reboots.

**Changes.** Changing `setype` modifies the rule. Changing `port` or `protocol` replaces the step, and `on_remove` decides what happens to the old rule.

## Removal

When you delete a `selinux_port` step, `on_remove` decides what happens on the host. The default, `"forget"`, keeps the rule. `"delete"` removes it with `semanage port -d`, and the port goes back to whatever the policy gives it.

## From Ansible

`conn3x convert ansible` turns `community.general.seport` tasks into `selinux_port` steps, with `ports`, `proto` and `setype`. `reload`, `ignore_selinux_state` and `local` are dropped. A task naming more than one port or range stays a TODO, since a step takes one: give each its own. So does `state: absent`. Where seport fails on a host without SELinux, unless `ignore_selinux_state` is set, this step does nothing, and the converted step says so in a note.
