# Roadmap

The full roadmap lives at [docs.conn3x.org/roadmap](https://docs.conn3x.org/roadmap). This is the short version. There are no dates, and nothing here works until a [release](https://github.com/conn3xorg/conn3x/releases) says it does.

## Today

- Linux hosts: Rocky Linux, RHEL, AlmaLinux, Fedora, Debian and Ubuntu, tested on every change.
- Windows Server 2022 and 2025 over OpenSSH, in preview: files, access rules, registry, services, features, users and groups, firewall rules, MSI packages, scheduled tasks and IIS, with a tested [Azure example](examples/azure-windows-server). Since v0.7.1 a circuit can also set a server's DNS servers and make it the first domain controller of a new Active Directory forest. Every Windows module is experimental.
- 125 official circuits, from nginx and PostgreSQL to k3s, Suricata and a private AI stack, in the [catalogue](https://docs.conn3x.org/circuits).
- The [Circuit Builder](https://conn3x.org/build), which writes a config from the circuits you pick, with host roles, an optional step that creates the servers too, and a link you can share.
- `conn3x convert ansible` for bringing playbooks across, and `conn3x drift` for both layers.
- Any OpenTofu provider. AWS, Azure, Google Cloud and DigitalOcean are tested end to end, each with a [tutorial](https://docs.conn3x.org/tutorials).

## Now

The rest of Active Directory on Windows. A new forest works; more domain controllers and joining a server to a domain don't yet. After those, a lab that builds a whole domain from one config.

## Next

Another round of circuits, then network devices: switches, routers and firewalls, in the same plan as the hosts behind them.

The first three device circuits are already out, and they're experimental: [RouterOS baseline](https://docs.conn3x.org/circuits/routeros-baseline), [OPNsense VLANs](https://docs.conn3x.org/circuits/opnsense-vlans) and [Proxmox VE network](https://docs.conn3x.org/circuits/proxmox-network). They go through community OpenTofu providers and were tested on virtual images, not hardware. What comes next is Conn3x talking to devices over their own CLI.

## Later

macOS hosts.

## Help shape it

Tell us what you'd want first in [Discussions](https://github.com/conn3xorg/conn3x/discussions), or pick up a [good first issue](https://github.com/search?q=org%3Aconn3xorg+label%3A%22good+first+issue%22+state%3Aopen&type=issues). [CONTRIBUTING.md](CONTRIBUTING.md) covers the rest.
