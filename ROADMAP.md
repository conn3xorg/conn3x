# Roadmap

The full roadmap lives at [docs.conn3x.org/roadmap](https://docs.conn3x.org/roadmap). This is the short version. There are no dates, and nothing here works until a [release](https://github.com/conn3xorg/conn3x/releases) says it does.

## Today

- Linux hosts: Rocky Linux, RHEL, AlmaLinux, Fedora, Debian and Ubuntu, tested on every change.
- 72 official circuits, from nginx and PostgreSQL to k3s, Suricata and a private AI stack, in the [catalogue](https://docs.conn3x.org/circuits).
- The [Circuit Builder](https://conn3x.org/build), which writes a config from the circuits you pick.
- `conn3x convert ansible` for bringing playbooks across, and `conn3x drift` for both layers.
- Any OpenTofu provider, with examples tested end to end on DigitalOcean and Google Cloud.

## Now

The Circuit Builder grows host roles (servers and agents, servers and clients), an optional step that creates the servers too, and a link you can share.

## Next

Windows hosts in the same plan as the cloud they run in, with tested Azure examples.

## After that

Network devices: switches, routers and firewalls over their own management interfaces.

## Later

macOS hosts.

## Help shape it

Tell us what you'd want first in [Discussions](https://github.com/conn3xorg/conn3x/discussions), or pick up a [good first issue](https://github.com/search?q=org%3Aconn3xorg+label%3A%22good+first+issue%22+state%3Aopen&type=issues). [CONTRIBUTING.md](CONTRIBUTING.md) covers the rest.
