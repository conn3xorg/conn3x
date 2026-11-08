# circuit-famwhen

A [Conn3x](https://conn3x.org) circuit converted from the Ansible role `famwhen` by `conn3x convert ansible -role`.

One thing still needs you. It's marked `TODO(convert)` in `main.circuit.hcl`, with the reason.

## Usage

```hcl
module "famwhen" {
  source = "./circuit-famwhen"

  hosts = {
    web1 = "203.0.113.10"
  }

  ssh_private_key_file = "~/.ssh/id_ed25519"
}
```

Then run `conn3x init` and `conn3x apply`.

## Variables

`hosts` and the `ssh_` variables say where to log in and how; see `variables.tf`.
