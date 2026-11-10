# A child domain on Azure

**Experimental.** Windows support is new and may change between releases.

Splitting a forest by region usually means a forest root you already have, and one more domain under it: `emea` under `lab`, with its own domain controller and a trust back to the root. By hand that's a wizard on each server, a DNS change, two reboots, and a credential prompt that refuses the admin's name in the form you'd type first. This builds both domains from one config, with [`windows_ad_forest`](https://docs.conn3x.org/modules/windows_ad_forest) and [`windows_ad_domain`](https://docs.conn3x.org/modules/windows_ad_domain), and the plan shows every step, reboots included, before anything changes.

Two Windows Server 2025 VMs come up:

| VM | Address | Role |
| --- | --- | --- |
| `dc1` | `10.46.0.4` | Makes the forest `lab.conn3x.test` and is its DNS server |
| `dc2` | `10.46.0.5` | Makes `emea.lab.conn3x.test`, a child of it, and is that domain's first DC |

## What it costs

Two `Standard_B2s_v2` VMs in `westus2`, with their disks and IPs, cost about $0.22 an hour. The apply took about 23 minutes, so a run with the checks below and the delete is about 15 cents. Delete it when you're done.

You need room for 4 vCPUs in the region; `az vm list-usage -l westus2 -o table` shows it.

## Run it

You need an Azure subscription, `az login`, Conn3x with `windows_ad_domain`, and an SSH key.

```sh
export ARM_SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
export TF_VAR_state_passphrase="$(openssl rand -hex 16)"   # keep this; state needs it
export TF_VAR_dsrm_password="a long password of your own" # never in plan or state
export TF_VAR_admin_cidrs="[\"$(curl -4 -s https://ifconfig.me)/32\"]"
export TF_VAR_admin_public_key_file=~/.ssh/id_ed25519.pub
export TF_VAR_admin_private_key_file=~/.ssh/id_ed25519

conn3x init
conn3x plan -out tfplan
conn3x apply tfplan
conn3x plan
```

The plan has 32 resources. In our run the second plan wanted one thing: a reboot of `dc1`, which Windows asked for on its own after servicing itself. It took two of those reboots before the plan was empty. See "What to know" below.

## Check it

```sh
ssh azadmin@$(conn3x output -json ips | jq -r .dc2) nltest /domain_trusts
```

`EMEA` should be the primary domain, and `LAB` the forest tree root, trusted in both directions.

## Tear it down

```sh
az group delete -n conn3x-ad-child-domain --yes
az group list -o table
```

## What happens, in order

1. Both VMs boot, and the bootstrap installs each one's host key.
2. `dc1` and `dc2` install AD DS at the same time.
3. `dc1` makes the forest, reboots, waits for Active Directory Web Services, and points its DNS at itself.
4. `dc2` points its DNS at `dc1`, then is promoted into the new child domain with the forest root's admin, named by its DNS name. Promotion adds a DNS delegation for `emea` in the root's zone.
5. `dc2` reboots. Its first boot as a domain controller took about 6 minutes, much longer than `dc1`'s.
6. Each domain admin's first password is replaced with one nobody knows.

## What to know

- **You log in the same way afterwards.** `ssh azadmin@<ip>` works on both. On `dc1` that's now `LAB\azadmin`, and on `dc2` it's `EMEA\azadmin`.
- **The admin is named by DNS name.** `windows_ad_domain` takes `azadmin@lab.conn3x.test`, not `LAB\azadmin`: the new DC finds the forest through DNS, and Windows refuses the NetBIOS form there.
- **State holds secrets of Azure's making.** `azurerm` keeps each VM's first admin password and the extensions' settings in state, host private keys included, so this example encrypts state. The child domain is made with `dc1`'s first password, and the last step replaces both, so those copies stop being useful. The host keys stay useful, so treat state as a secret.
- **`dc2` is handed an Enterprise Admin's password.** Adding a domain to a forest takes an Enterprise Admin, and the promotion runs on the new domain controller with that password as its input. So `dc2` holds it, in memory, from the promotion until the last step replaces it. Nothing less can do this job. What you can choose is the machine: promote only a server you'd trust with the forest.
- **Windows wants reboots of its own.** For the first half hour or so, Windows services itself even with automatic updates off, and that can leave a reboot pending. A plan in that window shows a reboot step. That's `only_if_pending` doing its job.
- **SSH is the only way in,** from `admin_cidrs` only. Both domain controllers still have public addresses, which is how you and Conn3x reach them. A forest you keep belongs behind a bastion or a VPN.
- **Windows doesn't patch itself here.** `patch_mode = "Manual"` and `automatic_updates_enabled = false` keep a surprise reboot out of the middle of an apply. That's right for an hour of testing and wrong for anything you keep: turn updates back on, or patch with `windows_update` steps.
- **It's a lab.** One DC per domain, AD on the OS disk, and the same DSRM password on both. Removing a step demotes nothing: delete the VMs for that.
