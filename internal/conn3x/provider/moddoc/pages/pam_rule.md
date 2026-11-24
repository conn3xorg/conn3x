Use `pam_rule` to keep one rule in a PAM service file, such as `pam_faillock.so` before `pam_unix.so` in `/etc/pam.d/common-auth`, or `remember=5` on a `password` rule. Conn3x finds the rule by its type, control and module, the way `community.general.pamd` does, and leaves comments, `@include` lines and the other rules as they are.

> **Warning:** a wrong PAM rule can stop everyone logging in, root over SSH with a password included. Before you apply a change to an `auth` or `account` rule, open a second root session on the host and keep it open until you've logged in again in a new one. When Conn3x logs in with a key, sshd skips the `auth` rules, so a plan that still works doesn't prove a password login does.

## Example usage

Count failed logins with `pam_faillock` before Ubuntu's `pam_unix` rule:

```hcl
step "faillock_preauth" {
  pam_rule {
    service   = "common-auth"
    type      = "auth"
    control   = "required"
    module    = "pam_faillock.so"
    arguments = ["preauth"]
    before    = "auth [success=1 default=ignore] pam_unix.so"
  }
}
```

Keep the last five passwords, and leave the rule's other arguments as they are:

```hcl
step "password_history" {
  pam_rule {
    service   = "common-password"
    type      = "password"
    control   = "[success=1 default=ignore]"
    module    = "pam_unix.so"
    arguments = ["remember=5"]
    state     = "args_present"
  }
}
```

Stop empty passwords working:

```hcl
step "no_nullok" {
  pam_rule {
    service   = "common-auth"
    type      = "auth"
    control   = "[success=1 default=ignore]"
    module    = "pam_unix.so"
    arguments = ["nullok"]
    state     = "args_absent"
  }
}
```

Take a rule out of a service:

```hcl
step "no_motd" {
  pam_rule {
    service = "sshd"
    type    = "session"
    control = "optional"
    module  = "pam_motd.so"
    state   = "absent"
  }
}
```
<!-- reference -->
## How it works

**Finding the rule.** A rule matches when its type, control and module are the same as the step's. The module must be written as the file writes it, so `pam_unix.so` doesn't match `/lib64/security/pam_unix.so`. A bracketed control matches however it's spaced inside the brackets. `-session` is its own type, and doesn't match `session`. Every rule that matches is changed, so where a file has `session required pam_env.so` twice, `args_present` adds the arguments to both.

**Reading the file.** Conn3x reads a service file as Linux-PAM does. A `#` starts a comment anywhere on a line, and a line ending in a backslash carries on to the next one. A rule it changes is written back on one line, with its comment. Lines Conn3x doesn't change stay byte for byte, along with the file's last newline, or the lack of one. A line that isn't a comment, an `@include` or a rule with a type, a control and a module is an error, saying which line, because Conn3x won't guess what PAM makes of it.

**When it fails.** Conn3x reads the file, and runs every check below on it, at the refresh before a plan for a step that's already applied, and at the apply for a new one. Either way it fails before anything is written.

**States.**

- `"present"` (default) keeps the rule. If it's there, it stays where it is, and `arguments`, when set, become its arguments, all of them. Unset, its arguments stay as they are. If it isn't there, it goes `before` or `after` the rule you name, which must be in the file once. With neither set, a missing rule is an error, since Conn3x won't guess where it goes.
- `"absent"` takes out every rule that matches. A missing file is already fine.
- `"args_present"` adds each argument to every matching rule. A `key=value` takes the place of the first argument with that key, so `remember=5` replaces `remember=3`. Anything else missing goes on the end. A rule that isn't there is an error.
- `"args_absent"` takes out each argument that matches exactly. `nullok` doesn't take out `nullok_secure`, and `remember` doesn't take out `remember=5`.

**Replacing a rule.** `replace` names a rule to turn into this one, in place. `replace = "auth required pam_tally2.so"` with `module = "pam_faillock.so"` changes the module and keeps the line where it was, and its arguments too unless you set `arguments`.

**Jumps.** A control such as `[success=1 default=ignore]` skips the next rule when the module succeeds. On Debian and Ubuntu, that's how `pam_unix` jumps over `pam_deny`. The count is of rules, so a rule added between a jump and where it lands changes where it lands. Adding before the jumping rule is safe. Adding after it, such as `pam_faillock.so authfail` after `pam_unix.so`, needs the jump raised by one. A second step can do that with `replace`, and the new rule's `after` then names `pam_unix.so` with its new control, with `depends_on` on that step.

**Safety.** Conn3x checks every type, control and module before connecting, since PAM fails the whole stack on a rule it can't read. It refuses an edit that would take the last `auth` rule out of a file that has one, so `state = "absent"` on a file's only `auth` rule fails, as does a `replace` that turns it into a `-auth` rule. Removing an `auth` rule while another stays is allowed, and that can still lock you out, so keep that second session open.

**authselect.** On Rocky Linux, RHEL, Fedora and other hosts that use `authselect`, it owns `system-auth`, `password-auth`, `postlogin`, `smartcard-auth`, `fingerprint-auth` and `switchable-auth`, and writes them again on its next `authselect apply-changes` or `authselect select`. When `/etc/authselect/authselect.conf` is there, a step for one of those files, or for any file that links into `/etc/authselect`, fails rather than make a change authselect will throw away. Make the change with a feature, such as `authselect enable-feature with-faillock`, or a custom profile from `authselect create-profile`, through a [`command`](command.md) step. Files authselect doesn't own, such as `sshd` or `su`, edit as usual.

**pam-auth-update.** On Debian and Ubuntu, `pam-auth-update` writes the `common-*` files. Once a step has changed one, `pam-auth-update` sees the change and stops updating them, saying so. `pam-auth-update --force` writes them again, without your rules, and the next plan shows the step out of sync.

**When it takes effect.** PAM reads the file each time a service starts a login, so the next login uses the new rule. Sessions already open keep working.

**Writing.** Conn3x writes the edited content the same way as [`file`](file.md): to a temporary file in the same directory, renamed over the old one, and relabelled with `restorecon` on SELinux hosts. If the service file is a symlink, the file it points to is written and the link stays. The file keeps its mode, owner and group. Steps that edit the same file take turns. `validate` can run a check on the edited file before it goes in.

**Missing files.** A missing service file is an error for `"present"` and `"args_present"`, and already fine for `"absent"` and `"args_absent"`.

## Removal

When you delete a `pam_rule` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the file as it is. `"delete"` takes out the rule for `state = "present"`, even one that was there before the step, or the arguments for `"args_present"`, and still refuses to take out the last `auth` rule. Neither can be put back for `"absent"` or `"args_absent"`, so `"delete"` isn't allowed with those.

## From Ansible

`conn3x convert ansible` turns `community.general.pamd` tasks into `pam_rule` steps. `name` becomes `service`, `module_path` becomes `module`, `module_arguments` becomes `arguments`, split at spaces as `pamd` splits them, and `path` is kept unless it's `/etc/pam.d`. `backup` becomes `backup = true`. Each state converts:

| `pamd` state | `pam_rule` |
| --- | --- |
| `updated` (default) | `"present"` with `arguments`, or with the new type, control or module and `replace` naming the old rule |
| `before`, `after` | `"present"` with the new rule and `before` or `after` naming the old one |
| `absent` | `"absent"` |
| `args_present`, `args_absent` | the same state with `arguments` |

The converted step does what the task does or less. Where `pamd` finds no rule to change and leaves the file alone, the step fails, naming the rule. `pamd` inserts a rule beside every match of the anchor; the step inserts it once, and fails when the anchor is in the file more than once.

A task stays a TODO with the reason when what the step would do could be more than the task:

- `before` or `after` with `module_arguments`. `pamd` gives the arguments only to a rule it inserts, and the step would set them on a matching rule that's already there.
- `updated` with both a new type, control or module and `module_arguments`, for the same reason.
- A bracketed `module_arguments` item, an argument with more than one `=`, or a bracketed control spaced other than `[value=action value=action]`, which `pamd` handles its own way.

So does a task with a state `pamd` doesn't have, one that leaves out `name`, `type`, `control` or `module_path`, one with a variable the converter can't fill in, one written as `key=value` text, and one with a loop.
