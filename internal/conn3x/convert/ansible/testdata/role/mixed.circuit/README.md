# circuit-mixed

A [Conn3x](https://conn3x.org) circuit converted from the Ansible role `mixed` by `conn3x convert ansible -role`.

12 things still need you. Each is marked `TODO(convert)` in `main.circuit.hcl`, with the reason.

## Usage

```hcl
module "mixed" {
  source = "./circuit-mixed"

  hosts = {
    web1 = "203.0.113.10"
  }

  ssh_private_key_file = "~/.ssh/id_ed25519"
}
```

Then run `conn3x init` and `conn3x apply`.

## Variables

`hosts` and the `ssh_` variables say where to log in and how; see `variables.tf`. The rest are the role's defaults:

| Name | Default |
| --- | --- |
| `mixed_mode` | `"0644"` |
| `mixed_conf_dir` | `"/etc/mixed"` |
