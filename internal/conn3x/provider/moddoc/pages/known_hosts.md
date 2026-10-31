Use `known_hosts` so a host can connect out to another machine over SSH without a prompt, by keeping that machine's key in a `known_hosts` file. It's what you want before a [`git`](/modules/git) step clones over SSH. Without `user`, the key goes in `/etc/ssh/ssh_known_hosts`, which every user trusts. Other entries in the file stay as they are.

## Example usage

Trust a server for everyone on the host:

```hcl
step "git_server" {
  known_hosts {
    host = "git.example.com"
    key  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICb82CHmmk5O4gbUZUpj9cjkk0Lju2Grj2V76NeuFamL"
  }
}
```

Trust one on another port, for one user:

```hcl
step "deploy_git" {
  known_hosts {
    host = "[git.example.com]:2222"
    key  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICb82CHmmk5O4gbUZUpj9cjkk0Lju2Grj2V76NeuFamL"
    user = "deploy"
  }
}
```

Stop trusting a retired server, whatever its keys were:

```hcl
step "old_server" {
  known_hosts {
    host  = "old.example.com"
    state = "absent"
  }
}
```
<!-- reference -->
## How it works

**Getting the key.** Check a key against a source you trust before you pin it. `ssh-keyscan` asks the server itself, so it's only as trustworthy as your network at that moment. `key` is the type and the key, with an optional comment, and no host name in front.

**Matching.** Keys are compared by type and key data, so a comment doesn't count. A host has one key per type: a different key of the same type replaces the old one, and a key of another type sits beside it. `git.example.com` and `[git.example.com]:2222` are separate entries, as they are to `ssh`.

**Other lines.** `host` is one literal, lowercase name or address. If an existing line lists it along with other names, those names keep their line. Hashed entries for the host are recognised. An existing hashed entry with the right key stays hashed, and new entries are written in plain text. Patterns such as `*.example.com` and `@cert-authority` or `@revoked` lines are left alone, so `state = "absent"` doesn't undo them.

**Reading.** Every plan reads the file and checks the entry. If someone changed or removed it by hand, `conn3x drift` reports the step, and the next apply puts it back.

**A user's file.** Conn3x looks the user up in the account database, and reads and writes `~/.ssh/known_hosts` as that user, so a symlink that user planted gets them nothing they couldn't already reach. A link at `known_hosts` gives way to the user's own file, and whatever it pointed at isn't touched. A new `~/.ssh` has mode `0700`, a new file has mode `0644`, and an existing file keeps its mode. The user has to exist, so put the step after the [`user`](/modules/user) step that creates them.

**The system file.** `/etc/ssh/ssh_known_hosts` is written like a [`file`](/modules/file) step, as the connecting user, so log in as root or set `become`. It keeps its mode and owner, a new one has mode `0644`, and a symlink there is followed.

**Changing a step.** Changing `host`, `key` or `user` replaces the step. With the default `on_remove`, Conn3x removes the old key and adds the new one.

## Removal

When you delete a `known_hosts` step, `on_remove` decides what happens on the host. The default, `"delete"`, removes that key, so a key you retire stops being trusted. `"forget"` leaves it in the file. Deleting a step with `state = "absent"` changes nothing.

## From Ansible

`conn3x convert ansible` turns `ansible.builtin.known_hosts` tasks into `known_hosts` steps, taking the host name off the front of `key`. Two kinds of `path` convert:

- `/etc/ssh/ssh_known_hosts` becomes a step without `user`.
- No `path`, or `~/.ssh/known_hosts`, becomes a step with `user` set to whoever Ansible runs as: `root` under `become`, otherwise the login user. If the play could change that user, through `become_user`, `remote_user`, `ansible_user`, `ansible_become` or `vars_files`, or there's an `ansible.cfg`, `group_vars` or `host_vars` beside the playbook, the task stays a TODO. Settings the converter can't see, such as an `ansible.cfg` elsewhere or `ANSIBLE_BECOME_USER`, still count, so check them if you use them.

A task stays a TODO with the reason when `path` is anything else, because Ansible may have acted there as root, leaving a file the user doesn't own. So does a task with `hash_host: yes`, or with `key` under `state: absent`, or whose `key` doesn't start with exactly its `name`: several names, a hashed name or a marker. So does a `name` with capitals, a loop, or `key=value` text.

Four things differ and can't be seen from the playbook. If a line lists this host with other names, Ansible rewrites or removes the whole line, and Conn3x keeps the other names. Ansible fails when `~/.ssh` is missing, and Conn3x creates it. On the system file, Ansible replaces a symlink, and Conn3x writes through it. Conn3x doesn't count a wildcard line as an entry for the host.
