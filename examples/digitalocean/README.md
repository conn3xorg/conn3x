# DigitalOcean

Create three Rocky Linux 10 droplets and set them up in the same plan: each gets a `deploy` account with your key. This is the example from [Why Conn3x is one tool](https://conn3x.org/blog/why-conn3x).

**This creates real droplets, which cost money while they exist.** Destroy them when you're done.

## What it shows

- **No inventory.** `hosts` is built from the droplets, so addresses never pass through a file.
- **Checked host keys from the first connection.** Each droplet's SSH host key is generated in the configuration and installed by cloud-init, then pinned with `host_key`.
- **No wait loop.** The `ssh` block's `timeout` keeps trying while a droplet boots.
- **One state.** The droplets, the host keys and the steps on each host are all in one state file.

## Run it

You need a DigitalOcean API token, an SSH key already in your account, its private half at `~/.ssh/id_ed25519`, and a key for the deploy user in `deploy.pub` beside `main.tf`.

```sh
export DIGITALOCEAN_TOKEN=...
cp ~/.ssh/id_ed25519.pub deploy.pub     # or any public key for the deploy user
conn3x init
conn3x plan -var ssh_key_id=<your key ID or fingerprint>
conn3x apply -var ssh_key_id=<your key ID or fingerprint>
```

The plan lists twelve changes: three host keys, three droplets, and an account and a key for each droplet.

Take `app-3` out of `local.servers` and plan again: the same plan destroys that droplet and removes its steps, deleting its deploy key first.

## Clean up

```sh
conn3x destroy -var ssh_key_id=<your key ID or fingerprint>
```
