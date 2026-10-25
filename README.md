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

Provisioning a server and configuring it are one job, but today it takes two tools:
Terraform or OpenTofu to create the machine, then Ansible to set it up, plus the glue
scripts, inventory files and second state that hold the two together. Conn3x is the
open-source tool we're building to do the whole job, from one binary, with one plan
and one state.

> **Early development.** Conn3x configures Linux hosts over SSH, as root or through
> sudo, on Rocky, RHEL, AlmaLinux, Fedora, Debian and Ubuntu. One plan can create a
> server and set it up, and we test that against real DigitalOcean droplets. Circuits
> already cover the everyday work: files and templates, packages and their
> repositories, services, users and SSH keys, cron jobs and timers, kernel parameters,
> mounts, the hostname and time zone, firewalld or ufw rules, SELinux booleans and
> file contexts, and checksummed downloads, archives and git checkouts. Every plan
> shows the exact diff. Star and watch the repo to follow along. We're building it in
> public.

<p align="center">
  <img alt="conn3x applying a circuit, then planning a fix for a hand-edited file" src=".github/assets/demo.gif" width="100%">
</p>

## What Conn3x will do

- **Show everything in one plan.** Before anything runs, you'll see the cloud resources
  about to be created and the exact file, package and service changes headed for the
  servers inside them, linked together. A droplet's IP flows straight into the nginx
  config that needs it.
- **Keep your providers and modules.** Conn3x is built on OpenTofu, so every Terraform and
  OpenTofu provider will work unchanged, and existing modules will load as they are.
- **Configure servers with Circuits.** Circuits are Conn3x's playbooks, written in HCL
  rather than YAML and Jinja. Each step reads the server, shows a diff, then applies
  it, and handlers run only when a step they watch changed. This part works today:

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
- **Leave nothing behind on your servers.** No Python on your hosts. Conn3x will push a
  small helper over SSH, or stick to plain shell commands where that's all you allow.

The first release targets Linux: Rocky, RHEL, AlmaLinux and Fedora, plus Debian and
Ubuntu. Network devices come next, then Windows.

## Built on OpenTofu

Conn3x starts from [OpenTofu](https://github.com/opentofu/opentofu) v1.13.2 and tracks its
releases. Files that come from OpenTofu keep their original copyright and license headers.
See [NOTICE](NOTICE). We're grateful to the OpenTofu and Terraform communities, whose
work makes provider compatibility possible.

## Contributing

Ideas and feedback are most useful right now, in
[Discussions](https://github.com/conn3xorg/conn3x/discussions). If you want to send code,
read [CONTRIBUTING.md](CONTRIBUTING.md) first. Every commit needs a DCO sign-off
(`git commit -s`). There's no CLA, and there never will be. See [GOVERNANCE.md](GOVERNANCE.md).

Found a security problem? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

Conn3x is licensed under the [Mozilla Public License 2.0](LICENSE).
