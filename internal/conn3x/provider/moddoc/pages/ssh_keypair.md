Use `ssh_keypair` to give a service account its own SSH key, such as a deploy user that pulls from a private git repository. Conn3x runs the host's `ssh-keygen`, so the private key is made on the host and never crosses the network or lands in state. Only the public key does, as `public_key`, ready to paste into your git host's deploy keys.

## Example usage

An ed25519 key for the `deploy` user:

```hcl
step "deploy_key" {
  ssh_keypair {
    path    = "/home/deploy/.ssh/id_ed25519"
    owner   = "deploy"
    comment = "deploy@web1"
  }
}
```

An RSA key, for a server that won't take ed25519:

```hcl
step "legacy_key" {
  ssh_keypair {
    path  = "/home/backup/.ssh/id_rsa"
    type  = "rsa"
    bits  = 4096
    owner = "backup"
  }
}
```
<!-- reference -->
## How it works

**Reading.** On every plan, Conn3x asks `ssh-keygen` for the public key of the private key at `path`, and reads its mode and owner and the `.pub` file beside it. The type and size come from the private key, never from the `.pub` file, which could be left over from another key. `in_sync` is true when the key is of the type and size asked for, has mode `0600` and the owner and group you set, and the `.pub` file holds its public key and `comment`.

**Making the key.** When there's no key at `path`, or one of another type or size, Conn3x runs `ssh-keygen` with no passphrase in a directory only its owner can read, then moves the key into place with mode `0600` and the public key beside it with mode `0644`. A file at `path` that isn't an SSH key `ssh-keygen` can read, such as one with a passphrase, is left alone, and the step fails.

**Keeping the key.** A key of the right kind is never made again. A change of mode, owner, group or `comment` only fixes the files, so the public key you registered with your git host keeps working.

**Changes.** Changing `type` or `bits` makes a new key, and `public_key` changes with it. Changing `path` replaces the step, and the old key is handled by its `on_remove`.

## Removal

`on_remove = "forget"`, the default, leaves both files. `on_remove = "delete"` removes the private key and the `.pub` file.
