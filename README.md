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

## What a plan looks like

Somebody changed nginx's port by hand on `web1`. The next `conn3x plan` reads the file back, shows the line that moved, and queues the reload that goes with it:

```text
  # conn3x_file.web__config["web1"] will be updated in-place
  ~ resource "conn3x_file" "web__config" {
      ~ content    = <<-EOT
            server {
          -   listen 8080;
          +   listen 80;
              server_name web1;
              root /var/www/html;
            }
        EOT
        id         = "127.0.0.1:40477:/etc/nginx/conf.d/web.conf"

Plan: 1 to add, 1 to change, 1 to destroy.
```

That's a real run, trimmed, of a circuit like the [quick start](#quick-start) below. The add and destroy are the `reload` handler: it's replaced so it runs once the file it watches has changed. Nothing touches the server until you run `conn3x apply`.

## Install

Linux, macOS and Windows, amd64 and arm64. Every release is signed and comes with SBOMs;
[the docs](https://docs.conn3x.org/install) show how to check one.

On macOS, with Homebrew:

```sh
brew install conn3xorg/tap/conn3x
```

To take a release only once it has been out for a week, use `conn3xorg/tap/conn3x@stable` instead, or the `:stable` image tag.

Or download a release:

```sh
VERSION=0.24.0 OS=linux ARCH=amd64   # or darwin / arm64
curl -fsSLO "https://github.com/conn3xorg/conn3x/releases/download/v${VERSION}/conn3x_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "conn3x_${VERSION}_${OS}_${ARCH}.tar.gz" conn3x && sudo install conn3x /usr/local/bin/
```

On Debian, Ubuntu, Rocky Linux, RHEL, AlmaLinux and Fedora, since v0.20.0, `apt install conn3x` and `dnf install conn3x` work from our signed repositories once you add them, and `apt upgrade` or `dnf upgrade` keeps Conn3x current. The [install page](https://docs.conn3x.org/install/) has the commands. Each release also has a `.deb` and an `.rpm` for amd64 and arm64, listed in the same signed `checksums.txt`.

On Windows, with [Scoop](https://scoop.sh):

```powershell
scoop bucket add conn3x https://github.com/conn3xorg/scoop-bucket
scoop install conn3x/conn3x
```

Or take the zip, which holds `conn3x.exe`, and put it somewhere on your `PATH`:

```powershell
$v = "0.24.0"
Invoke-WebRequest "https://github.com/conn3xorg/conn3x/releases/download/v$v/conn3x_${v}_windows_amd64.zip" -OutFile conn3x.zip
Expand-Archive conn3x.zip -DestinationPath conn3x
```

It logs in with keys from the Windows OpenSSH agent, like `ssh` does.

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
  PostgreSQL and MySQL databases and accounts, downloads, archives, git checkouts,
  reboots, waits and guarded commands, plus facts
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
  The default stays lockstep. A step with `when` runs only on the hosts where it's true,
  `run_once` runs it on just one, and `on` runs it on another host, as `delegate_to`
  does. `-limit` applies to some hosts only, and `batch_size` rolls a circuit out a few
  hosts at a time, stopping once too many fail.
- **Checks a file before it lands.** Give `file` a `validate` command, such as
  `visudo -cf %s`, and a broken `sudoers` or `sshd_config` never replaces the one that
  works. `conn3x convert ansible` carries it over from `copy` tasks. Add
  `confirm_after` to a file, template or firewall rule, and if the change cuts Conn3x
  off, the host puts the old one back by itself.
- **Reaches Windows Server too, in preview.** Files, access rules, the registry,
  services, users and groups, firewall rules, MSI packages, scheduled tasks, IIS,
  Windows Update, and Active Directory forests, child domains and new trees with their
  OUs, groups and users, on Windows Server 2022 and 2025, over OpenSSH. All 25 modules
  are out of experimental, and 21 take `import`, so a server you already run is adopted
  rather than set up again.
- **Starts on network devices, experimentally.** Arista EOS, Cisco IOS XE and classic
  IOS, Juniper Junos and VyOS steps configure a switch or router over its own CLI. Every
  change to a device comes with a timer that rolls it back if it cuts Conn3x off. Tested
  on cEOS-lab, IOS XE 17.18 and IOS 15.9 in Cisco Modeling Labs, vJunos-switch and a VyOS
  container, not yet on hardware. See
  [Network devices](https://docs.conn3x.org/network-devices).
- **Tells you what changed by hand.** `conn3x drift` reports changes made outside Conn3x,
  in the cloud and on your servers, and exits 2 when it finds some, so a scheduled job
  can alert on it.
- **Checks your circuits and keeps a record.** `conn3x lint` flags what the circuit
  grader marks down, such as a download without a checksum. `-report` on `apply` and
  `drift` writes each run to a JSON file, and `conn3x mcp` lets an AI assistant look up
  modules and circuits without ever running a plan. In `conn3x test`, `idempotent = true`
  fails a run whose second plan isn't empty.
- **Brings your playbooks.** `conn3x convert ansible -i inventory site.yml` turns a
  playbook into circuits and marks anything it can't translate for you to finish.
  The roles a playbook runs convert too, each into a circuit directory of its own, and
  `-role` converts a single role. Database tasks and `win_updates` come across as well.
  A `command` with shell characters, a Vault value or anything tagged `never` is left
  for you, with the reason.
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
IIS servers. All 25 Windows modules, Active Directory and `windows_update` included,
are out of experimental. Arista EOS, Cisco IOS XE and IOS, Juniper Junos and VyOS devices are experimental.
Windows at scale is the work now, then more network devices.
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
