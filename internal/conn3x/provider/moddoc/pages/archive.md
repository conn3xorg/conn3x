Use `archive` to unpack a tar or zip file that's already on the host into a directory. The `creates` path tells Conn3x the archive is unpacked: while it exists, nothing is unpacked again. To fetch the archive first, use [`download`](/modules/download).

## Example usage

Unpack a tarball:

```hcl
step "app_release" {
  archive {
    src     = "/opt/downloads/app-2.4.1.tar.gz"
    dest    = "/opt/app"
    creates = "/opt/app/app-2.4.1/bin/app"
  }
}
```

Unpack a zip file:

```hcl
step "web_assets" {
  archive {
    src     = "/opt/downloads/assets.zip"
    dest    = "/srv/www"
    creates = "/srv/www/assets/index.html"
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan checks whether `creates` exists on the host. The step is in sync while it does. Conn3x doesn't compare the unpacked files with the archive.

**Applying.** Conn3x creates `dest` if it's missing and unpacks into it, overwriting files that are already there. Files ending in `.zip` are unpacked with `unzip`. Anything else is unpacked with `tar`, which detects the compression itself. If `creates` still doesn't exist afterwards, the apply fails. Changing `src` or `creates` unpacks the archive again on the next apply.

**Requirements.** `src` must already be on the host, for example from a `download` step earlier in the circuit. Zip files need `unzip` installed. If it's missing, add a [`package`](/modules/package) step for it first.

## Removal

When you delete an `archive` step, Conn3x stops managing it and leaves the unpacked files where they are. `archive` has no `on_remove` argument.

## From Ansible

`conn3x convert ansible` turns `unarchive` tasks with `remote_src: true` and a `creates` path into `archive` steps. A task that unpacks a file from the controller, or has no `creates`, stays a TODO. For a file from the controller, download it first, then use an `archive` step.
