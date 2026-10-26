Use `selinux_fcontext` to add a local SELinux file context rule: files whose path matches `target` get the SELinux type `setype`. Conn3x relabels the files the rule covers, so a web root outside `/var/www` or a data directory in an unusual place gets the type its service needs. The rule applies on hosts with SELinux enabled, which in practice means the Red Hat family.

## Example usage

Label a web root, and everything under it, for the web server. `semanage` comes from the `policycoreutils-python-utils` package:

```hcl
step "semanage" {
  package {
    name = "policycoreutils-python-utils"
  }
}

step "www_context" {
  selinux_fcontext {
    target = "/srv/www(/.*)?"
    setype = "httpd_sys_content_t"
  }
}
```

Let the web server write to an upload directory:

```hcl
step "uploads_context" {
  selinux_fcontext {
    target = "/srv/www/uploads(/.*)?"
    setype = "httpd_sys_rw_content_t"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x lists the host's local rules with `semanage fcontext -l -C` and finds the one for `target`. `in_sync` is true when that rule gives `setype`. The step fails if SELinux isn't enabled, or if `semanage` isn't installed.

**Applying.** Conn3x adds the rule with `semanage fcontext -a`, or changes the existing rule with `-m`. It then runs `restorecon -R` on the directory in front of the first regular expression character in `target`, `/srv/www` for `/srv/www(/.*)?`, if that directory exists.

**Reboots.** Rules live in the SELinux policy store, so they hold across reboots and relabels.

**Changes.** Changing `setype` modifies the rule and relabels. Changing `target` replaces the step, and `on_remove` decides what happens to the old rule.

## Removal

When you delete a `selinux_fcontext` step, `on_remove` decides what happens on the host. The default, `"forget"`, keeps the rule. `"delete"` removes it with `semanage fcontext -d` and relabels the files it covered.

## From Ansible

`conn3x convert ansible` turns `community.general.sefcontext` tasks into `selinux_fcontext` steps. `reload` is dropped, since Conn3x always relabels. A task with `state: absent`, or with any other argument, such as `ftype` or `selevel`, stays a TODO.
