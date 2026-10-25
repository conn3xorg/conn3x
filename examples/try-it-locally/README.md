# Try it locally

Configure a throwaway Rocky Linux 10 container on your own machine. You don't need a server or a cloud account, just Conn3x and Podman or Docker. It takes about five minutes.

## Start the host

```sh
./up.sh
```

This builds a small image with `sshd`, starts it on `127.0.0.1:2222`, makes a fresh SSH key for it and records its host key in `./known_hosts`. Conn3x checks host keys on every connection, and this container is no exception. `up.sh` uses Podman if you have it, otherwise Docker; set `ENGINE=docker` to choose.

## Plan and apply

```sh
conn3x init
conn3x plan
```

The plan reads the container first, so it shows exactly what's missing: the `tree` package, a `deploy` user and a new `/etc/motd`. Then:

```sh
conn3x apply
conn3x plan
```

The second plan says `No changes.` That's how you know each step checked the host rather than just running.

## Change something by hand

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 'echo edited > /etc/motd'
conn3x drift
```

`drift` reports the edited file and exits 2. `conn3x plan` shows the line-by-line diff, and `conn3x apply` puts it back.

## Clean up

```sh
./down.sh
```

This removes the container, the key, the state and the provider cache from this directory.

## Next

Point `hosts` at a real server, or have a cloud provider create one in the same plan: see [digitalocean](../digitalocean).
