Use `repository` to add a third-party package repository and the key its packages are signed with. On Rocky Linux, RHEL, AlmaLinux and Fedora, Conn3x writes a `.repo` file for dnf; on Debian and Ubuntu, a `.sources` file for apt. A [`package`](/modules/package) step after it can then install from the repository.

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

In a real configuration, paste the repository's whole ASCII-armored key, or read it from a file next to your configuration with `key = file("${path.module}/files/docker.asc")`.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x works out the host's package manager and reads the repository's two files. `in_sync` is true when both exist with the content Conn3x would write.

**Red Hat family.** Conn3x writes the key to `/etc/pki/rpm-gpg/RPM-GPG-KEY-conn3x-<name>` and the repository to `/etc/yum.repos.d/<name>.repo`, enabled and with `gpgcheck=1`, pointing at the key. dnf reads the new repository on its next run.

**Debian and Ubuntu.** Conn3x writes the key to `/etc/apt/keyrings/conn3x-<name>.asc` and a deb822 file to `/etc/apt/sources.list.d/<name>.sources`, with `Signed-By` set to the key, so apt trusts the key for this repository only. `components` defaults to `["main"]`. A flat repository, whose suite ends in `/` such as `"./"`, gets no components. Conn3x then runs `apt-get update`, so the next step can install from the repository.

**Validation.** `url` must start with `http://` or `https://`, and `key` must be an ASCII-armored public key. Conn3x only learns the host's family when it connects, so a missing `suites` on Debian or Ubuntu fails at apply.

**Changes.** Changing `url`, `key`, `suites` or `components` rewrites the files. Changing `name` replaces the step, and `on_remove` decides what happens to the old files.

## Removal

When you delete a `repository` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the repository in place. `"delete"` removes its two files, and on Debian and Ubuntu runs `apt-get update`. Packages you installed from it stay installed.
