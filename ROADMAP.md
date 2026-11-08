# Roadmap

The full roadmap lives at [docs.conn3x.org/roadmap](https://docs.conn3x.org/roadmap). This is the short version. There are no dates, and nothing here works until a [release](https://github.com/conn3xorg/conn3x/releases) says it does.

The goal: anything you'd do with Terraform, OpenTofu, Ansible, Chef or Puppet, you'll be able to do with Conn3x.

## Today

- Linux hosts: Rocky Linux, RHEL, AlmaLinux, Fedora, Debian and Ubuntu, tested on every change.
- Windows Server 2022 and 2025 over OpenSSH, in preview: files, access rules, registry, services, features, users and groups, firewall rules, MSI packages, scheduled tasks and IIS, with a tested [Azure example](examples/azure-windows-server). A circuit can also build a small Active Directory domain: set a server's DNS servers, make it the first domain controller of a new forest, and, since v0.7.2, join other servers to the domain and promote a member to another domain controller, and since v0.7.3, keep the OUs, groups and users inside it. The [azure-domain example](examples/azure-domain) builds the forest, joins a server to it, and creates an OU, a user and a group with that user in it. Every Windows module is experimental.
- 127 official circuits, from nginx and PostgreSQL to k3s, Suricata and a private AI stack, in the [catalogue](https://docs.conn3x.org/circuits).
- The [Circuit Builder](https://conn3x.org/build), which writes a config from the circuits you pick, with host roles, an optional step that creates the servers too, and a link you can share.
- Adopting servers you already run: `import` on a step takes over what a Linux host already has, on 21 modules since v0.9.0, from `file` and `package` to `cron`, `mount` and firewall rules, and steps take OpenTofu's `lifecycle` block, from `prevent_destroy` to preconditions. `provider::conn3x::import_id` adopts what a shared circuit manages, and `conn3x generate step` writes the step from what's on the host. See [Adopt servers you already run](https://docs.conn3x.org/guides/adopt-servers).
- `strategy = "per_host"`, since v0.9.0, so a slow host doesn't hold up the others.
- Arista EOS switches over their own CLI, experimental since v0.9.0: `eos_config`, `eos_hostname` and `eos_vlan`, tested on cEOS-lab, not yet on hardware. See [Network devices](https://docs.conn3x.org/network-devices).
- `conn3x convert ansible` for bringing playbooks and, since v0.9.0, local roles across, and `conn3x drift` for both layers.
- Any OpenTofu provider. AWS, Azure, Google Cloud and DigitalOcean are tested end to end, each with a [tutorial](https://docs.conn3x.org/tutorials).

## Now

Windows at scale. A forest, member servers, more domain controllers, and the OUs, groups and users in the domain work, and the [azure-ad-lab](examples/azure-ad-lab) example builds a whole domain from one config. Since v0.9.0, [azure-windows-fleet](examples/azure-windows-fleet) builds a domain controller and up to five IIS servers from one apply. Next is many more Windows hosts in one apply, and the modules moving out of experimental. Promoting a domain controller straight from a workgroup server, child domains and the `ou` argument on a join are still untested, and a group can't list members from another domain.

## Next

Network devices over their own CLI, starting with Arista EOS: switches, routers and firewalls, in the same plan as the hosts behind them. The first three device circuits are already out, and they're experimental: [RouterOS baseline](https://docs.conn3x.org/circuits/routeros-baseline), [OPNsense VLANs](https://docs.conn3x.org/circuits/opnsense-vlans) and [Proxmox VE network](https://docs.conn3x.org/circuits/proxmox-network). They go through community OpenTofu providers and were tested on virtual images, not hardware. Since v0.9.0 Conn3x talks to Arista EOS itself, experimentally; next are one session per switch per apply, more EOS modules, then Junos, VyOS and classic Cisco IOS.

## After that

- Ansible roles and Galaxy: since v0.9.0 `conn3x convert ansible -role` turns one local role into a circuit. Next is pulling roles from Galaxy and converting a role's dependencies with it, rewriting what it can prove and marking the rest.
- Ad-hoc commands: run one thing on a group of hosts and see what comes back, without writing a circuit.
- A web UI: a self-hosted, open-source app for teams to run plans and applies, approve them, see history, schedule drift checks and keep credentials per project, in the spirit of [Semaphore UI](https://github.com/semaphoreui/semaphore) and AWX.

More circuits come alongside, when people ask for them.

## Toward full IaCC

The rest, in order. The full roadmap says where each one fits among the items above.

- The rest of OpenTofu on host steps. `import` and `lifecycle` on steps shipped in v0.8.0, and import on the rest of the Linux modules in v0.9.0; what's left is import on Windows.
- Inventory and host data: Ansible inventories with `group_vars` and `host_vars`, and values looked up by host, group and environment, as Hiera does.
- Rolling updates and orchestration: batches with a failure limit, run-once and delegated steps, tasks and plans like Bolt's.
- Servers that keep themselves right: scheduled applies from the web UI, run reports and host facts you can search, then a pull mode.
- Encrypted variable files you can commit, like Ansible Vault.
- Compliance checks that only report, a test command on containers, and policy on plans.
- Your own modules, converters for Chef cookbooks and Puppet modules, and a circuit registry.
- Runs that start on an event, such as an alert or a webhook.

## Later

macOS hosts.

## Help shape it

Every item above is broken into issues on the [Road to full IaCC](https://github.com/orgs/conn3xorg/projects/1) board, one [milestone](https://github.com/conn3xorg/conn3x/milestones) per theme. Comment on one to take it; if nobody has by the time we reach it, we'll take it ourselves, so nothing sits waiting.

Tell us what you'd want first in [Discussions](https://github.com/conn3xorg/conn3x/discussions), or pick up a [good first issue](https://github.com/search?q=org%3Aconn3xorg+label%3A%22good+first+issue%22+state%3Aopen&type=issues). [CONTRIBUTING.md](CONTRIBUTING.md) covers the rest.
