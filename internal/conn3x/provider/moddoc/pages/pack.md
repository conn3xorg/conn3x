Use `pack` to pack files on a host into a tar or zip archive, the way a backup or log-rotation role does before it ships them off. It's the other way round from [`archive`](/modules/archive), which unpacks one. Ansible rewrites the archive on every run; `pack` remembers what it packed, so a second plan is clean until a file changes.

## Example usage

Pack a directory into a gzipped tarball:

```hcl
step "app_logs" {
  pack {
    paths = ["/var/log/app"]
    dest  = "/backup/app-logs.tar.gz"
  }
}
```

Pack a config directory and some certificates into a zip file, leaving out what isn't wanted, for a backup user to read:

```hcl
step "etc_backup" {
  pack {
    paths   = ["/etc/nginx", "/etc/ssl/certs/*.pem"]
    dest    = "/backup/etc.zip"
    format  = "zip"
    exclude = ["/etc/nginx/*.dpkg-old", "/etc/nginx/cache"]
    group   = "backup"
    mode    = "0640"
  }
}
```
<!-- reference -->
## How it works

**What's packed.** Each of `paths` is a file or directory, packed with everything below it. A `*` or `?` in a path's last part matches names in its directory, so `/var/log/app/*.log` packs the logs there; as in the shell, names starting with a dot match only a pattern that starts with one. A path that matches nothing is skipped, but a path without a wildcard that isn't there fails the apply. Links are packed as links.

**Names in the archive.** They start from the deepest directory holding every path, as they do in Ansible. `paths = ["/var/log/app"]` packs `app/` and what's in it; `["/etc/nginx", "/etc/ssl/certs/*.pem"]` packs `nginx/...` and `ssl/certs/...`.

**Leaving things out.** Each of `exclude` is an absolute path or pattern, matched against the path of everything about to be packed. There, `*` and `?` match any characters, `/` too, so `/var/log/app/*.gz` leaves out every `.gz` file at any depth below it. A directory that matches is left out with everything in it. The archive itself is never packed, even when it's kept beside its files.

**When it's packed again.** Every refresh lists what would be packed and takes a SHA-256 over each entry's name, type, mode, owner, group, size and modification time. The step is in sync while the archive is there and that hash is the one in state, `sources_sha256`, from the last apply. A changed, added or removed file, or a deleted archive, plans a change, and apply packs everything again. File contents aren't read on refresh, so a large backup costs one `stat` per file, not a read of every byte. A file rewritten with the same size and modification time, which `touch -r` or `cp -p` can do, isn't noticed.

**Writing the archive.** It's written to a temporary file beside `dest` and moved into place, so `dest` is never half written. `dest`'s directory has to exist already, as it does for Ansible. `mode` defaults to `0600`, not to the umask, since an archive of `/etc` can hold secrets. `owner` and `group` are set on each apply. A change to `mode`, `owner` or `group` made by hand on the host isn't noticed.

**Formats.** `format` is `gz` (default), `bz2`, `xz`, `zstd`, `tar` or `zip`. Every format but `zip` is made by GNU `tar`, which runs `gzip`, `bzip2`, `xz` or `zstd`; `zip` is made by `zip`. Minimal images often have only `tar` and `gzip`. When a program is missing, the apply fails and names it, for example "xz isn't on this host, and format xz needs it". Put a [`package`](/modules/package) step for it first: `xz` is in `xz-utils` on Debian and Ubuntu.

**Who packs it.** As root, a step that reaches the files or `dest` through a directory another user owns works as that user, so it can't be led by a link of theirs to a file it shouldn't pack. That user then needs to be able to read the files and write `dest`.

## Converting from Ansible

`conn3x convert ansible` turns `community.general.archive` into a `pack` step. `path` becomes `paths` and `exclude_path` goes to `exclude` as it is. `exclusion_patterns`, which Ansible matches against names inside the archive, go to `exclude` below the archive's root, so `*.gz` becomes `/var/log/*.gz` for `path: /var/log/app`. A `pack` step leaves out a matched directory's contents too, which Ansible doesn't, so it packs less, never more. Without `mode`, the step notes that the archive is now `0600`.

What stays for review:

- `remove: true`, which deletes the files once they're packed. No plan can show that, and a `pack` step never deletes them.
- One path without a wildcard and a compressing format, unless `force_archive: true` is set. Ansible compresses a lone file on its own but tars a directory, and only `force_archive` says which this is. A `dest` named like a tarball, such as `.tgz`, doesn't count: if the path is a file, Ansible still writes plain gzip.
- No `dest`, a path with a trailing slash, a wildcard before a path's last part, or a `[` anywhere, which Ansible reads as a wildcard.
- `attributes` and the SELinux options.

## Removal

`on_remove = "forget"`, the default, leaves the archive where it is. `on_remove = "delete"` deletes the archive. The packed files are never touched.
