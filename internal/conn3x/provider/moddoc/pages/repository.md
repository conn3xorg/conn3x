Use `repository` to add a third-party package repository and the key its packages are signed with. On Rocky Linux, RHEL, AlmaLinux and Fedora, Conn3x writes a `.repo` file for dnf; on openSUSE and SUSE Linux Enterprise, a `.repo` file for zypper; on Debian and Ubuntu, a `.sources` file for apt. A [`package`](/modules/package) step after it can then install from the repository.

## Example usage

Add a repository on the Red Hat family. dnf expands `$releasever` and `$basearch` in the URL:

```hcl
step "docker_repo" {
  repository {
    name = "docker-ce"
    url  = "https://download.docker.com/linux/rhel/$releasever/$basearch/stable"
    key  = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----\n"
  }
}
```

Add a repository on Debian or Ubuntu, then install from it. apt needs `suites`:

```hcl
step "docker_repo" {
  repository {
    name       = "docker"
    url        = "https://download.docker.com/linux/ubuntu"
    key        = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----\n"
    suites     = ["noble"]
    components = ["stable"]
  }
}

step "docker" {
  package {
    name = "docker-ce"
  }
}
```

Add a repository from the Open Build Service on openSUSE Leap, ahead of the distribution's own, which zypper ranks at 99:

```hcl
step "shells_repo" {
  repository {
    name     = "shells"
    url      = "https://download.opensuse.org/repositories/shells/15.6/"
    key      = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----\n"
    priority = 90
  }
}
```

An Open Build Service repository serves its key at `repodata/repomd.xml.key` under its URL.

In a real configuration, paste the repository's whole ASCII-armored key, or read it from a file next to your configuration with `key = file("${path.module}/files/docker.asc")`.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x works out the host's package manager and reads the repository's two files. `in_sync` is true when both exist with the content Conn3x would write.

**Red Hat family.** Conn3x writes the key to `/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-<name>` and the repository to `/etc/yum.repos.d/<name>.repo`, enabled and with `gpgcheck=1`, pointing at the key. dnf reads the new repository on its next run.

**openSUSE and SUSE Linux Enterprise.** Conn3x writes the key to the same path and the repository to `/etc/zypp/repos.d/<name>.repo`, enabled, with `autorefresh=1`, `gpgcheck=1` and `type=rpm-md`, pointing at the key. zypper checks signatures against rpm's keyring, so Conn3x then runs `rpm --import` on the key, and `zypper --non-interactive refresh <name>`, so the next step can install from the repository. A key rpm already has imports again without change.

**Priority.** `priority` is the repository's rank for dnf and zypper: when two repositories offer a package, the one with the lower number wins. Leave it out for their default, 99. apt has no such setting in a source file, so a `priority` with `suites` is refused; rank apt repositories with a pin in `/etc/apt/preferences.d`, which a [`file`](/modules/file) step writes.

**Debian and Ubuntu.** Conn3x writes the key to `/etc/apt/keyrings/conn3x-<name>.asc` and a deb822 file to `/etc/apt/sources.list.d/<name>.sources`, with `Signed-By` set to the key, so apt trusts the key for this repository only. `components` defaults to `["main"]`. A flat repository, whose suite ends in `/` such as `"./"`, gets no components. Conn3x then runs `apt-get update`, waiting up to five minutes if another apt holds its lock, so the next step can install from the repository. Repository and package steps on one host take turns, so another circuit's install never runs beside this `apt-get update`.

**When the refresh fails.** If `apt-get update`, `rpm --import` or `zypper refresh` fails, for example because the key doesn't sign the repository, Conn3x puts both files back as they were before the apply: a file it created is removed, and a file that was already there gets its old content, mode and owner back. The apply then fails with the package manager's error, and the next plan shows the step to do again. A key `rpm --import` added to rpm's keyring before a failed `zypper refresh` stays there. dnf has no refresh at apply, so on the Red Hat family a bad key or URL shows up at the first `package` step that uses the repository.

**Marked as Conn3x's.** The `.repo` and `.sources` files start with `# Managed by Conn3x.`, so a [`package_sources`](/modules/package_sources) step, in this circuit or another, keeps them.

**Validation.** `url` must start with `http://` or `https://`, and `key` must be an ASCII-armored public key. Conn3x only learns the host's family when it connects, so a missing `suites` on Debian or Ubuntu fails at apply.

**Changes.** Changing `url`, `key`, `suites`, `components` or `priority` rewrites the files. Changing `name` replaces the step, and `on_remove` decides what happens to the old files.

## Removal

When you delete a `repository` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the repository in place. `"delete"` removes its two files, and on Debian and Ubuntu runs `apt-get update`. On the Red Hat family and SUSE, a key dnf or `rpm --import` put in rpm's keyring stays there. Packages you installed from it stay installed.

## From Ansible

`conn3x convert ansible` turns `apt_repository` tasks with a one-line `deb` source and `signed-by=/path`, and `yum_repository` tasks with one `baseurl`, one `gpgkey` and `gpgcheck: true`, and any `priority` from 1,, into `repository` steps. A `repository` step holds the key itself, so save it beside the playbook, in `files/` or next to it, under the same file name as the path or URL the task gives. `deb822_repository` tasks convert too: `name`, one entry in `uris`, one suite and any `components`, with `signed_by` as a URL or path to a key saved beside the playbook, or an armored key written inline. A fingerprint, `deb-src`, `enabled: false`, more than one URI or suite, and options such as `architectures` or `trusted` stay TODOs. The `apt_repository` step gets its name from the URL, suite and components, and carries a TODO to delete the `.list` file Ansible left behind. `description` is dropped. An `apt_key` task that sets only `url`, right before an `apt_repository` without `signed-by`, folds into that step, which takes the key from the URL's file name. So does an `rpm_key` task that sets only `key`, right before a `yum_repository` with the same `gpgkey`. When the repository task stays a TODO, its key task stays one too. A key task by itself stays a TODO: it trusts the key for every repository, and a `repository` step trusts it for one. So does a `keyserver` or `id` lookup. A task stays a TODO when its key file is missing, or with `state: absent`, `deb-src`, a `ppa:` source, an apt option other than `signed-by`, `filename`, `validate_certs`, `update_cache: false`, `enabled: false`, a `file` that differs from `name`, `metalink`, `mirrorlist`, a loop, or any other argument.

`community.general.zypper_repository` tasks with a `repo` URL and `auto_import_keys: true` become `repository` steps too, with `priority` if the task sets one. The task names no key: zypper imported the one the repository serves at `repodata/repomd.xml.key`, so save that as `files/<name>.key` beside the playbook. `description` is dropped, and `runrefresh` changes nothing, since the step always refreshes. A task stays a TODO without `auto_import_keys: true`, since its key then came from elsewhere, or with a `repo` naming a `.repo` file, `disable_gpg_check: true`, `enabled: false`, `autorefresh: false`, `state: absent`, `overwrite_multiple`, `remove_others`, a loop, or any other argument.
