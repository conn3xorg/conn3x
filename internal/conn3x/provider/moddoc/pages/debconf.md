Use `debconf` to answer a package's install-time questions before apt asks them. Some Debian and Ubuntu packages stop to ask something on first install: `postfix` wants its mailer type, `tzdata` its area, `iptables-persistent` whether to save the current rules. Preset the answer and the [package](/modules/package) step that follows installs without a prompt. It's what `debconf-set-selections` does from a preseed file, as a step that notices when the answer changes.

## Example usage

Install postfix as an internet site without the dialog:

```hcl
step "postfix_answers" {
  debconf {
    name     = "postfix"
    question = "postfix/main_mailer_type"
    vtype    = "select"
    value    = "Internet Site"
  }
}
```

A password question takes `value_wo`, so the secret stays out of plan and state:

```hcl
step "db_password" {
  debconf {
    name     = "app"
    question = "app/db_password"
    vtype    = "password"
    value_wo = "use an ephemeral variable here"
  }
}
```

In a real configuration, set `value_wo` from a variable with `ephemeral = true`, as [Secrets in files](/concepts#secrets-in-files) shows.
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x runs `debconf-show <name>` on the host and looks for `question` and its answer. `in_sync` is true when the answer is `value`. A question the host doesn't have yet is out of sync, so the first apply records it.

**Applying.** Conn3x feeds `name question vtype value` to `debconf-set-selections`, then reads the answer back: the tool exits 0 even on a line it skipped, so the step fails if the answer didn't take. Set the answer before the `package` step that installs the package; an answer set after the install doesn't change what the package already did.

**Passwords.** `debconf-show` prints `(password omitted)` for a password question, so for one Conn3x asks debconf itself, through `debconf-communicate`, for the answer the host has. With `value_wo`, state keeps only `value_hmac`, an HMAC of the answer keyed by `CONN3X_HMAC_KEY` or `~/.config/conn3x/hmac.key`; a refresh hashes the host's answer with the same key and compares. A password changed on the host shows up as drift and the next apply sets yours again, without the password ever reaching the plan or state. Every machine that runs this circuit needs the same key, as for a [file](/modules/file) with `content_wo`.

**Types.** `vtype` is the type the package's templates declare: `boolean`, `select`, `multiselect`, `string`, `password`, `text`, `note`, `title` or `error`. `debconf-set-selections` writes whatever it's given, so a `boolean` must be `true` or `false` here. A changed `vtype` is an update, but a type changed on the host isn't drift: only the answer is compared.

**Where it runs.** debconf is Debian and Ubuntu's. On a host in the Red Hat family the step fails and says so; give those hosts their own steps.

**Changes.** Changing `value`, `value_wo` or `vtype` updates the answer in place. Changing `name` or `question` is a different answer, so the plan replaces the step. There's no `on_remove`: removing the step leaves the answer in debconf.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.debconf` tasks that set a question into `debconf` steps. A `password` question gets a TODO to set `value_wo` from an ephemeral variable, since the converter never copies a secret. In a role, a `password` question in a task with `no_log` whose `value` is one role default and nothing else sets `value_wo` from that variable instead. Such a task converts only when every templated argument it passes is one role default and nothing else, such as `mysql_root_password`, that goes to a write-only argument; the variable is then `sensitive`, and also `ephemeral` when no other step reads it. Any other templated argument, or a secret written into the role, keeps the task a TODO. A task with only `name`, which lists a package's answers, and `vtype: seen` or `unseen: true`, which only touch the seen flag, stay for review.
