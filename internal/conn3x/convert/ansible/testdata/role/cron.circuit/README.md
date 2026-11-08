# circuit-cron

A [Conn3x](https://conn3x.org) circuit converted from the Ansible role `cron` by `conn3x convert ansible -role`.

Every task converted.

## Usage

```hcl
module "cron" {
  source = "./circuit-cron"

  hosts = {
    web1 = "203.0.113.10"
  }

  ssh_private_key_file = "~/.ssh/id_ed25519"
}
```

Then run `conn3x init` and `conn3x apply`.

## Variables

`hosts` and the `ssh_` variables say where to log in and how; see `variables.tf`.
