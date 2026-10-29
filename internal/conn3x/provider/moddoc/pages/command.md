Use `command` to run a shell command for what no module covers yet. A command can't be read back from the host like a file or a package, so give it a guard that says when it has done its job: `creates`, `removes` or `unless`. Conn3x then runs it only while the guard doesn't hold.

## Example usage

Run a command once, until the file it makes exists:

```hcl
step "certs" {
  command {
    command = "openssl req -x509 -newkey rsa:4096 -nodes -days 365 -subj /CN=localhost -keyout /etc/app/tls.key -out /etc/app/tls.crt"
    creates = "/etc/app/tls.crt"
  }
}
```

Run a command unless a check succeeds:

```hcl
step "swap" {
  command {
    command = "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile"
    unless  = "swapon --show=NAME --noheadings | grep -qx /swapfile"
  }
}
```

Run a command again whenever a value changes:

```hcl
step "migrate" {
  command {
    command  = "/opt/app/bin/migrate --to 42"
    triggers = { schema = "42" }
  }
}
```
<!-- reference -->
## How it works

**Guards.** `creates` holds while its path exists, `removes` while its path is missing, and `unless` while its check command exits with status 0. When you set more than one, all of them have to hold. `creates` and `removes` must be absolute paths.

**Reading.** Every plan checks the guards on the host. If they hold, the step has nothing to do. If they stopped holding, for example because someone deleted the file `creates` names, the plan runs the command again.

**Running.** The command runs with `/bin/sh`. Before running it, Conn3x checks the guards once more and skips the command if they now hold. A non-zero exit status fails the step, with what the command printed in the error. After a successful run, Conn3x checks the guards again and fails the step if they still don't hold, which usually means a guard doesn't match what the command does.

**Without guards.** A command with no guard runs when the step is created, and again only when `command` or `triggers` changes.

**Changes.** Changing `command`, `creates`, `removes`, `unless` or `triggers` runs the command again, subject to its guards.

**Output.** `stdout` and `stderr` keep the output of the last run, up to 4 KiB each. Both are sensitive, so the plan doesn't print them.

## Removal

Deleting a `command` step changes nothing on the host. To undo what a command did, add a step that does that.

## From Ansible

`conn3x convert ansible` turns `command` and `shell` tasks into `command` steps, carrying over `creates` and `removes`. `chdir` becomes `cd <dir> && ` in front of the command, and `executable` is dropped. Conn3x tests `creates` and `removes` as plain paths, so one with a glob such as `*` stays a TODO, as does a free-form command with `chdir=` or `creates=` written inline. A task with neither `creates` nor `removes` stays a TODO, since Ansible runs it on every play: add a guard or `triggers` so Conn3x knows when it's done.
