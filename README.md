<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/header-dark.gif">
    <img alt="Conn3x: one plan for your cloud and the servers it creates" src=".github/assets/header-light.gif" width="100%">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/conn3xorg/conn3x/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/conn3xorg/conn3x/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MPL-2.0" src="https://img.shields.io/badge/license-MPL--2.0-13233a"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/conn3xorg/conn3x"><img alt="OpenSSF Scorecard" src="https://img.shields.io/ossf-scorecard/github.com/conn3xorg/conn3x?label=openssf%20scorecard&cacheSeconds=86400"></a>
  <a href="https://www.bestpractices.dev/projects/16209"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/16209/badge"></a>
  <a href="https://github.com/conn3xorg/conn3x/discussions"><img alt="Discussions" src="https://img.shields.io/badge/discussions-join%20in-e85d0c"></a>
  <a href="https://www.codetriage.com/conn3xorg/conn3x"><img alt="Open Source Helpers" src="https://www.codetriage.com/conn3xorg/conn3x/badges/users.svg"></a>
  <a href="https://www.youtube.com/@conn3xlabs"><img alt="YouTube" src="https://img.shields.io/badge/youtube-watch-e85d0c?logo=youtube&logoColor=white"></a>
</p>

Conn3x creates your servers and sets them up, from one tool. You write one configuration
for the cloud resources and for the packages, files and services on them. `conn3x plan`
shows every change before it's made, and `conn3x apply` makes it. It works on servers you
already run, too.

That job usually takes two tools: Terraform or OpenTofu to create the machine, then
Ansible to set it up, plus the glue scripts and inventory files that hold the two
together. Conn3x does it from one binary, with one plan and one state, its record of what
it manages. We call that an IaCC tool: infrastructure as code and configuration management
in one plan. [Here's why that matters.](https://conn3x.org/blog/why-conn3x)

<p align="center">
  <img alt="conn3x applying a circuit, then planning a fix for a hand-edited file" src=".github/assets/demo.gif" width="100%">
</p>

## Install

Linux and macOS, amd64 and arm64. Every release is signed and comes with SBOMs;
[the docs](https://docs.conn3x.org/install) show how to check one.

On macOS, with Homebrew:

```sh
brew install conn3xorg/tap/conn3x
```

Or download a release:

```sh
VERSION=0.9.0 OS=linux ARCH=amd64   # or darwin / arm64
curl -fsSLO "https://github.com/conn3xorg/conn3x/releases/download/v${VERSION}/conn3x_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "conn3x_${VERSION}_${OS}_${ARCH}.tar.gz" conn3x && sudo install conn3x /usr/local/bin/
```

## Quick start

A circuit is a set of steps for a group of servers, written in HCL, the language Terraform
and OpenTofu use. If you know Ansible, it's like a playbook. Each step reads the server,
shows a diff, then applies it once you approve.

This circuit needs no cloud account, just a server you already have. It installs nginx,
writes its config from a template, keeps it running, and reloads it when the config
changes. Save it as `main.circuit.hcl` with your own address and login, and put your nginx
config beside it as `nginx.conf.tftpl`.

```hcl
circuit "web" {
  hosts = { web1 = "203.0.113.10" }
  ssh {
    user             = "deploy"
    private_key_file = "~/.ssh/id_ed25519"
    become           = true
  }

  step "nginx" {
    package {
      name = "nginx"
    }
  }
  step "config" {
    template {
      source      = "${path.module}/nginx.conf.tftpl"
      destination = "/etc/nginx/nginx.conf"
      vars        = { server_name = each.key }
    }
    notify = [handler.reload]
  }
  step "running" {
    service {
      name    = "nginx"
      state   = "started"
      enabled = true
    }
  }

  handler "reload" {
    service {
      name   = "nginx"
      action = "reload"
    }
  }
}
```

Connect to the server once with `ssh` first, because Conn3x always checks its host key.
Then run:

```sh
conn3x init && conn3x plan && conn3x apply
```

[Get started](https://docs.conn3x.org/get-started) walks through it in about fifteen
minutes. No server handy? [Try it locally](examples/try-it-locally) against a throwaway
container, in about five.

## What it does

- **One plan for the cloud and the servers in it.** Point a circuit's `hosts` at a
  cloud resource and the plan shows the server about to be created next to the exact
  file, package and service changes headed for it.
- **Keeps your providers, modules and state.** Conn3x is built on OpenTofu, so every
  Terraform and OpenTofu provider works unchanged.
- **Covers the everyday work.** Files, templates, and lines or blocks inside them;
  packages and repositories, services, users and SSH keys, cron jobs and timers,
  sysctl, mounts, the hostname, time zone and locale, firewalld and ufw, SELinux,
  downloads, archives, git checkouts, reboots, waits and guarded commands, plus facts
  about each host to plan with. [Every module](https://docs.conn3x.org/modules/file)
  is in the docs.
- **Takes over servers you already run.** Put `import = true` on a step and the first
  plan adopts the file, package, service or user that's already there instead of
  creating it, and shows only where the host and your circuit disagree. Steps take
  OpenTofu's `lifecycle` block too, so `prevent_destroy` and `ignore_changes` work on
  them. `conn3x generate step` reads what a host has and writes the step for you.
  [Adopt servers you already run](https://docs.conn3x.org/guides/adopt-servers)
  walks through it.
- **Doesn't wait on the slowest host.** Set `strategy = "per_host"` on a circuit and
  each host runs its own steps in order, so one slow server doesn't hold up the rest.
  The default stays lockstep.
- **Checks a file before it lands.** Give `file` a `validate` command, such as
  `visudo -cf %s`, and a broken `sudoers` or `sshd_config` never replaces the one that
  works. `conn3x convert ansible` carries it over from `copy` tasks.
- **Reaches Windows Server too, in preview.** Files, access rules, the registry,
  services, users and groups, firewall rules, MSI packages, scheduled tasks, IIS, and a
  small Active Directory domain with its OUs, groups and users, on Windows Server 2022
  and 2025, over OpenSSH. The
  [module pages](https://docs.conn3x.org/modules/windows_file) say what may still change.
- **Starts on network switches, experimentally.** `eos_config`, `eos_hostname` and
  `eos_vlan` steps configure an Arista EOS switch over its own CLI, with a revert
  timer that rolls a change back if it cuts Conn3x off. Tested on cEOS-lab, not yet
  on hardware. See [Network devices](https://docs.conn3x.org/network-devices).
- **Tells you what changed by hand.** `conn3x drift` reports changes made outside Conn3x,
  in the cloud and on your servers, and exits 2 when it finds some, so a scheduled job
  can alert on it.
- **Brings your playbooks.** `conn3x convert ansible -i inventory site.yml` turns a
  playbook into circuits and marks anything it can't translate for you to finish.
  `-role` turns an Ansible role into a circuit directory.
- **Borrows what others have written.** [conn3x.org/circuits](https://conn3x.org/circuits)
  lists shared circuits, such as nginx, users and a hardened baseline, that you add with
  one `module` block. Written one worth sharing? List it there.
- **Leaves nothing on your servers.** No Python, no agent. Conn3x connects over SSH,
  checks the host key every time, and runs plain shell commands, as root or through sudo.

## How it compares

| | Terraform or OpenTofu, plus Ansible | Conn3x |
| --- | --- | --- |
| Tools | Two, plus Python on the controller and the hosts | One binary |
| State | Terraform state for the cloud; none for hosts | One state for both |
| Preview of host changes | A separate `--check --diff` run | In the same plan as the cloud |
| Getting a new server's address into host config | Inventory scripts or plugins | A reference in the same config |
| Drift on hosts | Run the playbook in check mode | `conn3x drift`, for cloud and hosts |
| Servers that already exist | `import` for the cloud; nothing to adopt on hosts | `import` for both |

It's early. Conn3x configures Rocky, RHEL, AlmaLinux, Fedora, Debian and Ubuntu today,
and every change is tested on Rocky Linux 10, Fedora 45, Ubuntu 24.04 and Debian 13.
Windows Server 2022 and 2025 are in preview, with tested Azure examples for one server,
a small domain, a whole Active Directory lab, and a domain controller with up to five
IIS servers. Arista EOS switches are experimental. Windows at scale is the work now,
then more network devices.
See the [roadmap](ROADMAP.md).

## Built on OpenTofu

Conn3x starts from [OpenTofu](https://github.com/opentofu/opentofu) v1.13.2 and tracks its
releases. Files that come from OpenTofu keep their original copyright and license headers.
See [NOTICE](NOTICE). We're grateful to the OpenTofu and Terraform communities, whose
work makes provider compatibility possible.

## Contributing

Ideas and feedback are most useful right now, in
[Discussions](https://github.com/conn3xorg/conn3x/discussions). Releases and progress
go out on X at [@conn3xone](https://x.com/conn3xone) and on the
[blog](https://conn3x.org/blog), and short explainers on
[YouTube](https://www.youtube.com/@conn3xlabs). If you want to send code,
read [CONTRIBUTING.md](CONTRIBUTING.md) first. Every commit needs a DCO sign-off
(`git commit -s`). There's no CLA, and there never will be. See [GOVERNANCE.md](GOVERNANCE.md).

Found a security problem? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

Conn3x is licensed under the [Mozilla Public License 2.0](LICENSE).
