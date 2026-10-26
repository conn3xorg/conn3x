<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/header-dark.gif">
    <img alt="Conn3x: one plan for your cloud and the servers it creates" src=".github/assets/header-light.gif" width="100%">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/conn3xorg/conn3x/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/conn3xorg/conn3x/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: MPL-2.0" src="https://img.shields.io/badge/license-MPL--2.0-13233a"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/conn3xorg/conn3x"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/conn3xorg/conn3x/badge"></a>
  <a href="https://github.com/conn3xorg/conn3x/discussions"><img alt="Discussions" src="https://img.shields.io/github/discussions/conn3xorg/conn3x?color=e85d0c"></a>
</p>

Provisioning a server and configuring it are one job, but it usually takes two tools:
Terraform or OpenTofu to create the machine, then Ansible to set it up, plus the glue
scripts, inventory files and second state that hold the two together. Conn3x does the
whole job, from one binary, with one plan and one state.
[Here's why that matters.](https://conn3x.org/blog/why-conn3x)

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
VERSION=0.6.3 OS=linux ARCH=amd64   # or darwin / arm64
curl -fsSLO "https://github.com/conn3xorg/conn3x/releases/download/v${VERSION}/conn3x_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "conn3x_${VERSION}_${OS}_${ARCH}.tar.gz" conn3x && sudo install conn3x /usr/local/bin/
```

## Quick start

Circuits are Conn3x's playbooks: HCL, beside the rest of your infrastructure. Each step
reads the server, shows a diff, then applies it.

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

```sh
conn3x init && conn3x plan && conn3x apply
```

[Get started](https://docs.conn3x.org/get-started) walks through it in about fifteen
minutes. No server handy? [Try it locally](examples/try-it-locally) against a throwaway
container, in about five.

## What it does

- **One plan for the cloud and the servers in it.** Point a circuit's `hosts` at a
  resource and the plan shows the droplet about to be created next to the exact file,
  package and service changes headed for it.
- **Keeps your providers, modules and state.** Conn3x is built on OpenTofu, so every
  Terraform and OpenTofu provider works unchanged.
- **Covers the everyday work.** Files, templates, and lines or blocks inside them;
  packages and repositories, services, users and SSH keys, cron jobs and timers,
  sysctl, mounts, the hostname, time zone and locale, firewalld and ufw, SELinux,
  downloads, archives, git checkouts, reboots, waits and guarded commands, plus facts
  about each host to plan with. [Every module](https://docs.conn3x.org/modules/file)
  is in the docs.
- **Tells you what changed by hand.** `conn3x drift` reports drift across both layers
  and exits 2 when it finds some, so a scheduled job can alert on it.
- **Brings your playbooks.** `conn3x convert ansible -i inventory site.yml` turns a
  playbook into circuits and marks anything it can't translate for you to finish.
- **Leaves nothing on your servers.** No Python, no agent. Conn3x connects over SSH,
  checks the host key every time, and runs plain shell commands, as root or through sudo.

## How it compares

| | Terraform or OpenTofu, plus Ansible | Conn3x |
| --- | --- | --- |
| Tools | Two, plus Python on the controller and the hosts | One binary |
| State | Terraform state for the cloud; none for hosts | One state for both |
| Preview of host changes | A separate `--check --diff` run | In the same plan as the cloud |
| Cloud addresses into host config | Inventory scripts or plugins | An expression |
| Drift on hosts | Run the playbook in check mode | `conn3x drift`, both layers |

It's early. Conn3x configures Rocky, RHEL, AlmaLinux, Fedora, Debian and Ubuntu today,
and every change is tested on Rocky Linux 10, Fedora 45, Ubuntu 24.04 and Debian 13.
Network devices come next, then Windows.

## Built on OpenTofu

Conn3x starts from [OpenTofu](https://github.com/opentofu/opentofu) v1.13.2 and tracks its
releases. Files that come from OpenTofu keep their original copyright and license headers.
See [NOTICE](NOTICE). We're grateful to the OpenTofu and Terraform communities, whose
work makes provider compatibility possible.

## Contributing

Ideas and feedback are most useful right now, in
[Discussions](https://github.com/conn3xorg/conn3x/discussions). Releases and progress
go out on X at [@conn3xone](https://x.com/conn3xone) and on the
[blog](https://conn3x.org/blog). If you want to send code,
read [CONTRIBUTING.md](CONTRIBUTING.md) first. Every commit needs a DCO sign-off
(`git commit -s`). There's no CLA, and there never will be. See [GOVERNANCE.md](GOVERNANCE.md).

Found a security problem? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

Conn3x is licensed under the [Mozilla Public License 2.0](LICENSE).
