Use `patch` when a fix ships as a `.patch` file: a one-line change to a vendor's config, a backported fix to a script you don't own. It applies a unified diff with GNU `patch`, or takes it out again, and every refresh tells you which of the two the host has. It's `ansible.posix.patch`, with the check written down.

## Example usage

Apply a patch kept beside the circuit to one file:

```hcl
step "tools" {
  package {
    name = "patch"
  }
}

step "fix_conf" {
  depends_on = [conn3x_package.docs__tools]

  patch {
    # Usually file("${path.module}/files/app-conf.patch"), kept with the circuit.
    content = <<-EOT
      --- app.conf
      +++ app.conf
      @@ -1 +1 @@
      -workers = 2
      +workers = 8
    EOT
    dest    = "/etc/app/app.conf"
  }
}
```

The address is the step's resource address, `conn3x_package.CIRCUIT__STEP`, here in a circuit named `docs`.

Apply a patch that touches several files in a tree, made with `diff -ru a/ b/` or `git diff`, and take it out again later:

```hcl
step "backport" {
  patch {
    # Usually file("${path.module}/files/backport.patch").
    content = <<-EOT
      --- a/src/main.c
      +++ b/src/main.c
      @@ -1 +1 @@
      -int retries = 3;
      +int retries = 5;
    EOT
    basedir = "/opt/app"
    strip   = 1
    state   = "absent"
  }
}
```
<!-- reference -->
## How it works

**Where the patch comes from.** `content` is the patch itself, usually `file()` on a patch kept with the circuit, so it's in the plan and in state. `src` reads a patch file that's already on the host, for one an earlier step downloaded or wrote.

**Where it goes.** `dest` names the one file to patch, and the file names inside the patch are ignored. `basedir` is the directory the patch's own file names start from, for a patch that touches several files; `strip` takes leading directories off those names, so `strip = 1` turns `a/src/main.c` into `src/main.c`, as `patch -p1` does.

**Applied or not.** Every refresh dry-runs the patch both ways. If it reverses cleanly, it's in and `status` is `applied`. If it applies cleanly, it's out and `status` is `not_applied`. A file someone reverted by hand shows as `not_applied`, out of sync, and the next apply puts the patch back.

**Neither.** When the patch fits neither way, `status` is `conflict`: the file has changed since the patch was written, perhaps by a package upgrade. Apply then fails with the hunks `patch` couldn't place, and changes nothing. It never forces a patch in or writes `.rej` and `.orig` files beside yours. Update the patch, or the file, and apply again.

**Options.** `ignore_whitespace` and `binary` go to `patch` as `--ignore-whitespace` and `--binary`, for every dry run and apply. `patch` keeps its default fuzz, as Ansible does.

**A changed patch.** Changing `content` or `src` applies the new patch on top of what's there. When the new one replaces the old rather than adding to it, take the old one out first with `state = "absent"`, or write the new patch against the original file and use a new step with `on_remove = "delete"` on the old.

**The tools.** `patch` comes with the `patch` package, which minimal images often leave out. When it's missing, the step says so. Put a `package` step before it.

## Converting from Ansible

`conn3x convert ansible` turns `ansible.posix.patch` into a `patch` step. A `src` on the controller, Ansible's default, is read from `files/` beside the playbook or role and becomes `content = file(...)`. With `remote_src: true`, `src` stays a path on the host. `backup` is dropped, since the plan shows the change. A task that sets both `dest` and `basedir` stays for review.

## Removal

`on_remove = "forget"`, the default, leaves the files as they are. `on_remove = "delete"` takes the patch out when it's in, and fails, changing nothing, when it fits neither way.
