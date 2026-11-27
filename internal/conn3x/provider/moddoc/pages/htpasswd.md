Use `htpasswd` to keep one user's line in a password file for basic auth, the file Apache's `AuthUserFile` and nginx's `auth_basic_user_file` read. Conn3x hashes the password with bcrypt on this machine, so the host needs neither `htpasswd` nor Python's passlib, and the password never goes into state.

## Example usage

An `admin` login for a web UI behind nginx:

```hcl
step "web_admin" {
  htpasswd {
    path        = "/etc/nginx/.htpasswd"
    name        = "admin"
    password_wo = "use an ephemeral variable here"
    create      = true
    mode        = "0640"
    group       = "www-data"
  }
}
```

Set `password_wo` from a variable with `ephemeral = true`, so the password stays out of the plan file too.
<!-- reference -->
## How it works

**The line.** The file holds one `name:hash` line per user. This step looks after only its own user's line. It's changed where it is, or added at the end, and every other line is left as it was. The hash is bcrypt with a `$2y$` prefix, as `htpasswd -B` writes it. Changing `name` renames the user: the old name's line becomes the new one, in the same place, so the old name can't log in any more. If the file has two lines for one name, from a hand edit, Conn3x changes the first, which is the one Apache and nginx read, and leaves the rest.

**The password.** `password_wo` is write-only, so neither state nor the plan holds it. State keeps `password_hmac`, an HMAC of the password made with Argon2id first and keyed with your Conn3x key. A new password changes that value, and the plan shows a change. Since a bcrypt hash has its own random salt, Conn3x can't tell from the file what password it holds. If someone changes the hash by hand, Conn3x doesn't notice until you give a new `password_wo`.

**Reading.** On every plan, Conn3x checks that the user's line is in the file, and that the mode, owner and group are as set. A missing line puts the step out of sync, and the next apply writes it again. A change to only `mode`, `owner` or `group` keeps the hash that's there.

**The file.** Without `create = true`, a missing file is an error. A file it creates gets `mode`, or `0644` if you don't set one, so set `mode` and `group` to keep the hashes from everyone on the host.

## Removal

When you delete an `htpasswd` step, `on_remove` decides what happens on the host. The default, `"forget"`, leaves the line. `"delete"` takes the user's line out and leaves the rest of the file.

## From Ansible

`conn3x convert ansible` turns `community.general.htpasswd` tasks into `htpasswd` steps. `path` (or `dest`), `name` (or `username`), `mode`, `owner` and `group` carry over. `create` is set, since Ansible's default is to create the file. The task's `password` is never copied: a TODO says to set `password_wo` from an ephemeral variable. In a role, a task with `no_log` whose `password` is one role default and nothing else sets `password_wo` from that variable instead. Such a task converts only when every templated argument it passes is one role default and nothing else, such as `mysql_root_password`, that goes to a write-only argument; the variable is then `sensitive`, and also `ephemeral` when no other step reads it. Any other templated argument, or a secret written into the role, keeps the task a TODO. Ansible's default `hash_scheme` is `apr_md5_crypt`, so unless the task asked for `bcrypt`, a note says Conn3x writes bcrypt instead. `state: absent` stays a TODO.
