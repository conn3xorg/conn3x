Use `package_sources` to keep a host to the package sources you've chosen: the distribution's own, the ones [`repository`](/modules/repository) steps added, and any you name in `keep`. Conn3x moves every other source file aside, where apt and dnf no longer read it. It's for "this host takes packages only from the repositories we list", which a security team checks for.

## Example usage

Keep only the distribution's sources and Conn3x's, on any host:

```hcl
step "only_our_sources" {
  package_sources {}
}
```

Keep Ubuntu Pro's sources too, and drop Rocky's devel repository, which the distribution ships:

```hcl
step "only_our_sources" {
  package_sources {
    keep   = ["ubuntu-esm-apps.sources", "ubuntu-esm-infra.sources"]
    remove = ["rocky-devel.repo"]
  }
}
```
<!-- reference -->
## How it works

**What it reads.** Every plan lists the files the package manager reads added sources from:
- **Debian and Ubuntu:** the `.list` and `.sources` files in `/etc/apt/sources.list.d`. `/etc/apt/sources.list` itself is left alone.
- **Red Hat family:** the `.repo` files in `/etc/yum.repos.d`. Fedora keeps its own repositories in `/usr/share/dnf5/repos.d`, which is left alone too.

**What stays.** A file stays when it's one of these:
- **Conn3x's.** Its first line is `# Managed by Conn3x.`, which every `repository` step writes, from any circuit. So a step here never fights the repositories other circuits add.
- **The distribution's.** On Debian and Ubuntu, `<ID>.sources`, such as `ubuntu.sources`, with `ID` from `/etc/os-release`. On the Red Hat family, a file owned by a package whose name starts with `<ID>-repos`, such as `rocky-repos` or `fedora-repos-modular`. On RHEL, `redhat.repo` too, which subscription-manager writes.
- **In `keep`.**

`remove` names a distribution file that should go anyway. Naming a file a `repository` step wrote is refused, since the two steps would undo each other on every apply: delete that step instead.

**What goes.** Every other file is moved to `/var/lib/conn3x/disabled-sources`, keeping its name, and on Debian and Ubuntu Conn3x then runs `apt-get update`. If a file of that name is already there, the older one is kept as `<name>.~1~`. A wrong guess costs a `mv` back, not a hunt for the original file. Keys in `/etc/apt/keyrings` and `/etc/pki/rpm-gpg` stay where they are: a key with no source left is harmless.

**Check before the first apply.** Ubuntu cloud images often carry `ubuntu-esm-apps.sources` and `ubuntu-esm-infra.sources` from Ubuntu Pro, and they're the first files most people see moved aside. List them in `keep` if the host should go on getting those updates. CentOS Stream's and Oracle Linux's repository packages don't follow the `<ID>-repos` name, so list their files in `keep`.

**The plan.** The step's `unlisted` holds the name of each file it would move, never its contents, since a private repository's URL can carry a token. The plan shows them going, and a warning names them.

**Root.** Moving files in `/etc` needs root: set `become = true` in the circuit's `ssh` block unless Conn3x logs in as root.

**More than one.** Two `package_sources` steps on one host, from one circuit or several, agree unless their `keep` and `remove` differ. Give each host one.

**Changing it.** Changing `keep` or `remove` updates the step in place.

## Removal

Deleting a `package_sources` step changes nothing on the host. The files it moved stay in `/var/lib/conn3x/disabled-sources` until you move them back.

## From Ansible

Ansible has no single module for this, so `conn3x convert ansible` has nothing to turn into a `package_sources` step.
