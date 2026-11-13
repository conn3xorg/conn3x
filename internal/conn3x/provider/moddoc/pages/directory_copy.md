Use `directory_copy` to ship a directory from the machine Conn3x runs on to a host: a static site, a folder of config, a bundle of scripts. It's what `ansible.posix.synchronize` does in a playbook, without rsync on either end.

Conn3x reads the source when it plans, and the host's copy when it refreshes, and compares them file by file by SHA-256. Only a file whose content, mode or owner differs is written, each one the way a [`file`](/modules/file) step writes a file: atomically, with its mode and owner, under the same checks on [paths as root](/guides/paths-as-root). Binary files are fine.

The plan says which files will change. The step's `files` map holds each file's path and sum, so a change shows as one line per file:

```text
  ~ files       = {
      ~ "index.html"   = "68f01b289aedcf28e96fce1f9444365e83b9bfc7e1bf32df20f1f15966835316" -> "737e6daf77521604fc482aa91e8bed8c47f4815c624e61e49c45ecbb5832f708"
      - "stray.txt"    = "73cb3858a687a8494ca3323053016282f3dad39d42cf62ca4e79dda2aac7d9ac" -> null
        # (2 unchanged elements hidden)
    }
```

That's `index.html` edited on the host, and `stray.txt` put there by hand with `delete = true` on. A file with the right content but the wrong mode or owner shows its sum with the mode and owner it has, such as `(mode 0600, owner root:root)`.

With `delete = true`, files under `destination` that the source doesn't have are removed, as rsync's `--delete` does. It's off by default, so files something else put there stay. Empty directories are left behind either way.

## Example usage

```hcl
step "site" {
  directory_copy {
    source      = "${path.module}/site"
    destination = "/var/www/site"
    owner       = "www-data"
    delete      = true
  }
}
```

<!-- reference -->

## Notes

- The source must be on the machine that plans and applies, CI included. A relative path is relative to where Conn3x runs, so write `${path.module}/site`.
- Only regular files are copied. A link or a special file in the source is an error, so what lands on the host is what you can see in the tree.
- A step copies up to 5,000 files and 1 GiB. A tree bigger than that belongs in a package or an image.
- Each changed file is its own write, so a first copy of thousands of files is slow. After that, only the files that differ are sent.
- If the source changes between plan and apply, the apply stops and asks you to plan again, so it never writes files the plan didn't show.
- Removing the step leaves the files, unless `on_remove = "delete"`, which removes the files the step last copied and nothing else.
