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
Give a command a secret on standard input, not on its command line, passed in at run time:

```hcl
step "registry_login" {
  command {
    command  = "podman login --username ci --password-stdin registry.example.com"
    stdin_wo = "use an ephemeral variable here"
    creates  = "/root/.config/containers/auth.json"
  }
}
```
Give the command, and its `unless`, variables of their own:

```hcl
step "install" {
  command {
    command = "make install"
    creates = "/usr/local/bin/app"
    environment = {
      PREFIX = "/usr/local"
    }
  }
}
```

Run a command only when an earlier step left the host needing it. The probe reads after `php`, during the apply when `php` has a change pending, so it sees the package that step installed:

```hcl
circuit "web" {
  hosts = { web1 = "203.0.113.10" }
  ssh {
    user = "root"
  }

  step "php" {
    package {
      name = "php-cli"
    }
  }

  probe "has_gmp" {
    command = "php -m | grep -qx gmp"
  }

  step "build_gmp" {
    only_if = data.conn3x_command.web__has_gmp[each.key].exit_code != 0
    command {
      command = "/usr/local/src/php-gmp/build.sh"
      creates = "/usr/local/lib/php/gmp.so"
    }
  }
}
```
<!-- reference -->
## How it works

**Guards.** `creates` holds while its path exists, `removes` while its path is missing, and `unless` while its check command exits with status 0. When you set more than one, all of them have to hold. `creates` and `removes` must be absolute paths.

**Reading.** Every plan checks the guards on the host. If they hold, the step has nothing to do. If they stopped holding, for example because someone deleted the file `creates` names, the plan runs the command again.

**Running.** The command runs with `/bin/sh`. Before running it, Conn3x checks the guards once more and skips the command if they now hold. A non-zero exit status fails the step, with what the command printed in the error. After a successful run, Conn3x checks the guards again and fails the step if they still don't hold, which usually means a guard doesn't match what the command does.

**Without guards.** A command with no guard runs when the step is created, and again only when `command` or `triggers` changes.

**Secrets.** A command line is visible to every user on the host for as long as the command runs, in `ps` and in `/proc`. So a secret doesn't belong in `command`. Put it in `stdin_wo` and have the command read it from standard input, which most tools can do: `--password-stdin`, `--from-file=-`, a trailing `-`, or `read -r token` in a shell script. `stdin_wo` is write-only: state records only `stdin_hmac`, a keyed hash that tells Conn3x when the value changed. If the command prints the value back, Conn3x blanks it from `stdout`, `stderr` and the error. `unless` never gets it, since a plan doesn't have write-only values, and `unless` is itself a command line, so keep secrets out of it too.

**With only_if.** A step's [`only_if`](/reference/circuits/steps#only_if) decides at apply whether the command may run. It doesn't make it run: a command that already ran doesn't run again because `only_if` is true again. It runs when a command step always runs, when it's created, when its guards stop holding, or when `command` or `triggers` changes. So if it should run again once what it did is undone, give it a guard that sees that, such as `creates` above. While `only_if` is false it doesn't run at all, guards or not.

**Changes.** Changing `command`, `stdin_wo`, `creates`, `removes`, `unless` or `triggers` runs the command again, subject to its guards.

**Output.** `stdout` and `stderr` keep the output of the last run, up to 4 KiB each. Both are sensitive, so the plan doesn't print them.

Sensitive hides them from the plan, not from state: the state file keeps both in plain text, so anyone who can read your state can read them. When a command fails, the last ten lines it printed are also in the error, which goes to the terminal, to `-json` output and to a `-report` file. Don't print a secret from a command step. If a command has to produce one, such as a join token, have it write the secret to a file on the host with mode `0600`, and read it there.

## Removal

Deleting a `command` step changes nothing on the host. To undo what a command did, add a step that does that.

## From Ansible

`conn3x convert ansible` turns `command` and `shell` tasks into `command` steps, carrying over `creates` and `removes`. A task's `environment:` mapping becomes the step's `environment`; on another module it stays a TODO. `chdir` becomes `cd <dir> && ` in front of the command. A `shell` task's `executable`, such as `/bin/bash`, runs the command as Ansible's `shell` does, as `'/bin/bash' -c '<command>'`, since a `command` step runs `/bin/sh`, which is dash on Debian and Ubuntu. A `command` task's `executable` is dropped, as Ansible ignores it there. `stdin` becomes `stdin_wo`, with the newline Ansible adds unless `stdin_add_newline` is `false`. It's kept out of state, and `stdin_hmac` plans a change when the text changes. Conn3x tests `creates` and `removes` as plain paths, so one with a glob such as `*` stays a TODO. Written inline, as in `command: make install creates=/usr/local/bin/x chdir=/src`, these options convert as they would under `args:`: like Ansible, the converter takes `creates=`, `removes=`, `chdir=`, `executable=`, `stdin=`, `stdin_add_newline=`, `strip_empty_ends=` and `warn=` out of the line, and every other word stays in the command, `foo=bar` included. A task with neither `creates` nor `removes` stays a TODO, since Ansible runs it on every play: add a guard or `triggers` so Conn3x knows when it's done.

A `script` task becomes a `command` step as well. The script goes in `stdin_wo`, read with `file()` from the playbook's `files/` (a role's `files/` is copied into the circuit), and the step saves it with `mktemp`, runs it with its arguments and deletes it. Saving it first means a command in the script that reads standard input gets nothing, rather than the rest of the script. The interpreter is `executable` if the task sets it, and otherwise the script's `#!` line, as the kernel would read it. Only `sh` and `bash` convert, since every host has them; a Python or PowerShell script, a script with no `#!` line and one encrypted with Ansible Vault stay TODOs. `chdir`, `creates` and `removes` carry over as for `command`, and a task with neither guard stays a TODO. A changed script plans the step again, through `stdin_hmac`, but `creates` and `removes` still hold it off, as in Ansible.

In a role, a `stat` task with `path` and `register` becomes `data "conn3x_command"`, run on every host at plan time, when every task before it only reads. Its command is `[ -e 'PATH' ] || [ -L 'PATH' ]`, which matches `stat`'s default `follow: false`: a dangling link still exists. A later `when: X.stat.exists` becomes `data.conn3x_command.X[each.key].exit_code == 0`, and `not X.stat.exists` its negation. The data source reads no file contents, so a probe of a private key doesn't copy the key into state, and it works on directories, big files and files the login user can't read. A `when` on any other field, such as `X.stat.isdir` or `X.stat.checksum`, stays a TODO that names the field, as do `follow: true`, any other argument such as `get_checksum`, and a path starting with `~` or holding a template the converter can't fill in.

A probe that runs after tasks that change the host, a `stat` or a `command` with `register` and `changed_when: false`, becomes the circuit's `probe` block instead, at the task's place, so it reads after every step above it. The tasks whose `when` reads it get `only_if` on the probe, such as `only_if = data.conn3x_command.php__php_installed[each.key].exit_code != 0`, and keep the rest of the `when`, on role defaults and facts, as their `when`. A probe with a `when` reads every host, since it only reads. A `command` probe converts this way only with `failed_when: false` or `ignore_errors: true`: Ansible stops the play when it exits non-zero, and a circuit probe hands the exit code over instead. A gated `command` without `creates` or `removes` converts with a TODO(convert) note, since it won't run again when `only_if` turns true again.

`when: x is changed`, where nothing else reads `x`, becomes `triggers = [<x's step>[each.key].revision]` on a `command` step, when the task that registers `x` became one step on every host. It runs on the first apply too, which the step's TODO(convert) note points out. On any other module it stays a TODO: notify a handler from `x` for a restart or a reload.

`community.general.apache2_module` becomes a `command` step too, as circuit-apache writes it: `a2enmod -q NAME` with `unless = "test -e /etc/apache2/mods-enabled/NAME.load"`, or `a2dismod -q NAME` (with `-f` for `force`) when `state: absent`. Like Ansible's module, it works only on Debian and Ubuntu. A loop, a name that isn't a plain module name, and `ignore_configcheck` stay TODOs.

Ansible's `command` module runs a program with plain arguments, and a `command` step runs its text through `/bin/sh`. So a `command` task with `;`, `|`, `$`, `*`, `>`, a backslash or other characters a shell reads stays a TODO: `echo one ; echo two` prints one line in Ansible and would run two commands in a step. A `shell` task already means the shell, and converts as it is.

Ansible's list form, `argv`, converts as well: `command: {argv: [/usr/bin/touch, /tmp/x]}` becomes `command = "'/usr/bin/touch' '/tmp/x'"`, each argument quoted so the step's shell hands the program the words Ansible did. A templated argument is filled in the same way `cmd` is. An `argv` that isn't a list of plain values, an empty one, or one beside `cmd`, which Ansible refuses, stays a TODO.

The two modules part company on expansion: `shell` joins a list with `shlex.quote` and expands nothing, which quoting matches exactly, but `command` passes every argument through `expanduser` and `expandvars` first. So an argument starting with `~`, or holding `$NAME` or `${NAME}`, stays a TODO with a reason that names it, since a quoted word would give the program the text instead of the value. Add `expand_argument_vars: false` to have `command` mean exactly what quoting does, and the task converts. A `$` that starts no variable, as in `awk '{print $1}'`, is left as it is by Ansible too, so it converts.

A play that sets `become_user`, or `remote_user` without `become`, or that has `ansible.cfg`, `group_vars`, `host_vars` or a `vars_files` file beside it setting who its tasks run as, sends these tasks to review with the reason, because a command does what its user can do. A circuit runs as root under `become` and otherwise as its login user.
