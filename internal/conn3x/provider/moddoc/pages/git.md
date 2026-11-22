Use `git` to keep a checkout of a repository on a host at a branch, tag or commit. The host runs `git` itself, so it needs `git` installed and access to the repository.

## Example usage

Check out a tag:

```hcl
step "app_source" {
  git {
    repo = "https://github.com/conn3xorg/conn3x.git"
    dest = "/opt/src/conn3x"
    ref  = "v0.4.0"
  }
}
```

Follow a branch, so each apply moves the checkout to the branch's latest commit:

```hcl
step "site" {
  git {
    repo = "https://github.com/example/site.git"
    dest = "/srv/site"
    ref  = "main"
  }
}
```

Keep only the latest commit of a large repository you only deploy from:

```hcl
step "theme" {
  git {
    repo  = "https://github.com/example/theme.git"
    dest  = "/srv/theme"
    ref   = "main"
    depth = 1
  }
}
```

Clone a private repository with a deploy key, after pinning its server's host key. Steps run in the order they're written, so the key is in place first:

```hcl
step "github_host_key" {
  known_hosts {
    host = "github.com"
    key  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
  }
}

step "app" {
  git {
    repo     = "git@github.com:example/app.git"
    dest     = "/srv/app"
    ref      = "main"
    key_file = "/root/.ssh/app_deploy"
  }
}
```

Pin a commit, given in full:

```hcl
step "pinned" {
  git {
    repo = "https://github.com/example/site.git"
    dest = "/srv/site-pinned"
    ref  = "0123456789abcdef0123456789abcdef01234567"
  }
}
```
<!-- reference -->
## How it works

**Reading.** Every plan reads the commit checked out at `dest` and asks the remote, with `git ls-remote`, which commit `ref` points to. The step is in sync when they're the same, so a plan notices when a branch moves on the remote. A full 40-character commit isn't looked up on the remote. Without `ref`, Conn3x follows the remote's default branch. Short commit hashes aren't accepted.

**Applying.** If `dest` has no repository, Conn3x clones into it. It then fetches from the remote when the commit isn't already there, and checks the commit out with a detached `HEAD`. The checkout is forced, so local changes to tracked files are discarded. Untracked files are left alone. The `commit` attribute records the commit checked out.

**Shallow checkouts.** With `depth`, the clone and every fetch take only that many commits of history, and tags aren't fetched, since they'd bring the history back. Conn3x fetches `ref` by name, which every git server allows. With a full commit as `ref`, it fetches the commit by its hash, which some servers refuse depending on their `uploadpack` settings. Changing `depth` on an existing checkout doesn't reclone it: the next fetch uses the new depth. Removing `depth` fetches the rest of the history, so the checkout is whole again.

**Requirements.** The host needs `git`. If it's missing, add a [`package`](/modules/package) step for it first. For a private repository, the host needs its own credentials for it: an SSH key, or for https a `.netrc` or credential helper in the home directory of the user who runs the step. `repo` can't hold a user name or password for https, since it's in the plan, the state and the host's process list.

**Deploy keys.** With `key_file`, every command that talks to the remote (`ls-remote`, clone and fetch) logs in through `ssh -i <key_file> -o IdentitiesOnly=yes -o BatchMode=yes`. Only that key is offered, and ssh never waits for a password. `key_file` works with `ssh://` and `git@` repositories only. The key stays on the host, so it's never in the plan or the state. The server's host key isn't accepted blindly: put it in `known_hosts` first, with a [`known_hosts`](/modules/known_hosts) step.

**Plain http.** Nothing checks what an `http://` repository sends, so it's only accepted with a full commit as `ref`, which the content has to match. Use `https://` or SSH for a branch or tag.

## Removal

When you delete a `git` step, Conn3x stops managing it and leaves the checkout where it is. `git` has no `on_remove` argument.

## From Ansible

`conn3x convert ansible` turns `git` tasks into `git` steps, with `version` becoming `ref`, and `depth` and `key_file` kept as they are. `accept_hostkey` and `accept_newhostkey` aren't carried over: the converted step gets a note to add a `known_hosts` step for the server instead. `force: true` needs nothing, because a `git` step always discards changes to tracked files. Without it, Ansible stops when the checkout has local changes, so the converted step carries a note saying that it won't stop. `update: false` is left for review.
