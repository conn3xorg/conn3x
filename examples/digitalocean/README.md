# DigitalOcean

Create three Rocky Linux 10 droplets and set them up in the same plan: each is closed to everyone but you, and gets a `deploy` account with your key. This is the example from [Why Conn3x is one tool](https://conn3x.org/blog/why-conn3x).

**This creates real droplets, which cost money while they exist.** Destroy them when you're done.

## What it shows

- **No inventory.** `hosts` is built from the droplets, so addresses never pass through a file.
- **Checked host keys from the first connection.** Each droplet's SSH host key is generated in the configuration and installed by cloud-init, then pinned with `host_key`.
- **No wait loop.** The `ssh` block's `timeout` keeps trying while a droplet boots.
- **One state.** The droplets, the firewall, the host keys and the steps on each host are all in one state file, which this example encrypts.

## Run it

You need a DigitalOcean API token, an SSH key already in your account, its private half at `~/.ssh/id_ed25519`, and a key for the deploy user in `deploy.pub` beside `main.tf`.

```sh
export DIGITALOCEAN_TOKEN=...
export TF_VAR_state_passphrase="$(openssl rand -hex 16)"   # keep this; state needs it
export TF_VAR_admin_cidrs="[\"$(curl -4 -s https://ifconfig.me)/32\"]"
export TF_VAR_ssh_key_id=<your key ID or fingerprint>
cp ~/.ssh/id_ed25519.pub deploy.pub     # or any public key for the deploy user
conn3x init
conn3x plan
conn3x apply
```

The plan lists 25 changes: three host keys, three droplets, a firewall, and six steps on each droplet.

Take `app-3` out of `local.servers` and plan again: the same plan destroys that droplet and removes its steps, deleting its deploy key first.

## What to know

- **The host key travels in user data, and the droplet can read it back.** DigitalOcean has one way to hand a new droplet anything, and that's user data. Its metadata service then serves the user data to any process on the droplet that asks, with no login, for the droplet's whole life. So the host's private key is there for every local user to read, and whoever has it can pass for that host to Conn3x. The first four steps close that: an nftables rule lets only root reach the metadata service, and it's in place before the `deploy` account exists. Checked on Rocky Linux 10: as `deploy`, the request is refused, before and after a reboot.
- **That rule has a cost.** DigitalOcean's monitoring agent asks the metadata service as its own user. If you turn monitoring on, allow that user in the rule too.
- **State holds the host keys.** `tls_private_key` keeps each private key in state, and the droplet's user data repeats it. That's why state and saved plans are encrypted here. Lose the passphrase and the state can't be read; leak the state and passphrase together and the host keys go with them.
- **SSH is the only way in,** from `admin_cidrs` only. The cloud firewall is what stands between root's SSH login and the internet, so don't widen it to `0.0.0.0/0`.
- **Conn3x logs in as root.** That's what a new droplet offers. Root can only log in with your key, never a password. To stop using root after the first run, give `deploy` sudo and switch the `ssh` block to it with `become = true`.

## Clean up

```sh
conn3x destroy
```
