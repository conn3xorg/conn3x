Use `locale` to set a host's system locale, the `LANG` in its locale configuration. A host has one system locale, so a circuit needs only one `locale` step.

## Example usage

Set a UTF-8 locale on Debian or Ubuntu, where Conn3x generates it if it's missing:

```hcl
step "locale" {
  locale {
    name = "en_GB.UTF-8"
  }
}
```

On the Red Hat family, install the locale's language pack first:

```hcl
step "langpack" {
  package {
    name = "glibc-langpack-en"
  }
}

step "locale" {
  locale {
    name = "en_US.UTF-8"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x reads `LANG` from `/etc/default/locale` where `update-locale` exists, as on Debian and Ubuntu, and from `/etc/locale.conf` elsewhere. Encodings compare the way `locale -a` spells them, so `en_US.UTF-8` matches `en_US.utf8`.

**Installing the locale.** If `locale -a` doesn't list the locale and `locale-gen` exists, Conn3x enables it in `/etc/locale.gen` and runs `locale-gen`. On the Red Hat family there's no `locale-gen`, so the locale has to come from a `glibc-langpack-<language>` package; without it the step fails and names the package to install.

**Applying.** Conn3x runs `update-locale` where it exists, then `localectl set-locale`, and writes `/etc/locale.conf` itself if neither works. All three keep the setting across reboots.

## Removal

A `locale` step has no `on_remove`. When you delete it, Conn3x stops managing the locale and leaves the host as it is.

## From Ansible

`conn3x convert ansible` turns `community.general.locale_gen` tasks that name one locale into `locale` steps. `locale_gen` only generates a locale, while a `locale` step also makes it the host's `LANG`, so the step carries a TODO saying so. A task with `state: absent`, several locales or a loop, or a second `locale_gen` task in the same play, stays a TODO.
