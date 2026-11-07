# Roadmap

The full roadmap lives at [docs.conn3x.org/roadmap](https://docs.conn3x.org/roadmap). This is the short version. There are no dates, and nothing here works until a [release](https://github.com/conn3xorg/conn3x/releases) says it does.

## Today

- Linux hosts: Rocky Linux, RHEL, AlmaLinux, Fedora, Debian and Ubuntu, tested on every change.
- Windows Server 2022 and 2025 over OpenSSH, in preview: files, access rules, registry, services, features, users and groups, firewall rules, MSI packages, scheduled tasks and IIS, with a tested [Azure example](examples/azure-windows-server). A circuit can also build a small Active Directory domain: set a server's DNS servers, make it the first domain controller of a new forest, and, since v0.7.2, join other servers to the domain and promote a member to another domain controller. The [azure-domain example](examples/azure-domain) builds the forest and joins a server to it. Every Windows module is experimental.
- 125 official circuits, from nginx and PostgreSQL to k3s, Suricata and a private AI stack, in the [catalogue](https://docs.conn3x.org/circuits).
- The [Circuit Builder](https://conn3x.org/build), which writes a config from the circuits you pick, with host roles, an optional step that creates the servers too, and a link you can share.
- `conn3x convert ansible` for bringing playbooks across, and `conn3x drift` for both layers.
- Any OpenTofu provider. AWS, Azure, Google Cloud and DigitalOcean are tested end to end, each with a [tutorial](https://docs.conn3x.org/tutorials).

## Now

Windows at scale. A forest, member servers and more domain controllers work. Organizational units, groups and users come next, then a lab that builds a whole domain, and what's in it, from one config, then many Windows hosts in one apply and the modules moving out of experimental. Promoting a domain controller straight from a workgroup server, child domains and the `ou` argument on a join are still untested.

## Next

Network devices over their own CLI, starting with Arista EOS: switches, routers and firewalls, in the same plan as the hosts behind them. The first three device circuits are already out, and they're experimental: [RouterOS baseline](https://docs.conn3x.org/circuits/routeros-baseline), [OPNsense VLANs](https://docs.conn3x.org/circuits/opnsense-vlans) and [Proxmox VE network](https://docs.conn3x.org/circuits/proxmox-network). They go through community OpenTofu providers and were tested on virtual images, not hardware.

## After that

- Ansible roles and Galaxy: `conn3x convert ansible` turns a role into a circuit, rewriting what it can prove and marking the rest.
- Ad-hoc commands: run one thing on a group of hosts and see what comes back, without writing a circuit.
- A web UI: a self-hosted, open-source app for teams to run plans and applies, approve them, see history, schedule drift checks and keep credentials per project, in the spirit of [Semaphore UI](https://github.com/semaphoreui/semaphore) and AWX.

More circuits come alongside, when people ask for them.

## Later

macOS hosts.

## Help shape it

Tell us what you'd want first in [Discussions](https://github.com/conn3xorg/conn3x/discussions), or pick up a [good first issue](https://github.com/search?q=org%3Aconn3xorg+label%3A%22good+first+issue%22+state%3Aopen&type=issues). [CONTRIBUTING.md](CONTRIBUTING.md) covers the rest.
