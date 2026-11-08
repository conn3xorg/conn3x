# circuit-svc

A [Conn3x](https://conn3x.org) circuit converted from the Ansible role `svc` by `conn3x convert ansible -role`.

Every task converted.

## Usage

```hcl
module "svc" {
  source = "./circuit-svc"

  hosts = {
    web1 = "203.0.113.10"
  }

  ssh_private_key_file = "~/.ssh/id_ed25519"
}
```

Then run `conn3x init` and `conn3x apply`.

## Variables

`hosts` and the `ssh_` variables say where to log in and how; see `variables.tf`.

These take each host's OS family's value from the role's `vars/` unless you set them:

| Name | Debian and Ubuntu | Red Hat family |
| --- | --- | --- |
| `svc_user` | `www-data` | `nobody` |
