# An Active Directory lab on Azure

**Experimental.** Windows support is new and may change between releases.

A lab domain is the thing you need for an afternoon and never want to build. Two domain controllers, two member servers, some OUs and users: by hand that's four RDP sessions, three wizards, a DNS change on every box and six reboots. This builds all of it from one config with [circuit-active-directory](https://github.com/conn3xorg/circuit-active-directory), and the plan shows you every step, reboots included, before anything changes.

Four Windows Server 2025 VMs come up:

| VM | Address | Role |
| --- | --- | --- |
| `dc1` | `10.46.0.4` | Makes the forest `lab.conn3x.test`, then the directory |
| `dc2` | `10.46.0.5` | Joins, then becomes the second domain controller |
| `srv1` | `10.46.0.6` | Member server, in `OU=Servers,OU=Lab` |
| `srv2` | `10.46.0.7` | Member server, in `OU=Servers,OU=Lab` |

The directory gets the OUs `Lab`, `Lab/Servers` and `Lab/People`, the users `alice` and `bob`, and the groups `LabAdmins` (alice) and `Helpdesk` (alice and bob).

## What it costs

Four `Standard_B2s_v2` VMs in `westus2`, with their disks and IPs, cost about $0.44 an hour. One run from nothing, with the checks below and the delete, took about 27 minutes, so about 20 cents. Delete it when you're done: left up, it's about $10 a day.

You need room for 8 vCPUs in the region. A new pay-as-you-go subscription can start with less; `az vm list-usage -l westus2 -o table` shows it.

## Run it

You need an Azure subscription, `az login`, Conn3x v0.7.3 or later, and an SSH key.

```sh
export ARM_SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
export TF_VAR_state_passphrase="$(openssl rand -hex 16)"   # keep this; state needs it
export TF_VAR_dsrm_password="a long password of your own" # never in plan or state
export TF_VAR_user_passwords='{alice="one for alice", bob="one for bob"}'
export TF_VAR_admin_cidrs="[\"$(curl -4 -s https://ifconfig.me)/32\"]"
export TF_VAR_admin_public_key_file=~/.ssh/id_ed25519.pub
export TF_VAR_admin_private_key_file=~/.ssh/id_ed25519

conn3x init
conn3x plan -out tfplan
conn3x apply tfplan
conn3x plan
```

The plan has 59 resources. The apply took about 16 minutes, and the second plan said `No changes.`

## Check it

```sh
ssh azadmin@$(conn3x output -json ips | jq -r .dc1) repadmin /replsummary
ssh azadmin@$(conn3x output -json ips | jq -r .srv1) powershell Test-ComputerSecureChannel
```

`repadmin` should show both DCs with 0 failures, and the member should say `True`.

## Tear it down

Delete the resource group. That's the whole lab, and nothing in it is worth keeping:

```sh
az group delete -n conn3x-ad-lab --yes
az group list -o table
```

`conn3x destroy` works too, but it asks each Conn3x step to forget its host first, which is slower and gets you nothing here.

## What happens, in order

1. All four VMs boot, and the bootstrap installs each one's host key.
2. `dc1` and `dc2` install AD DS at the same time.
3. `dc1` makes the forest, reboots, and waits for AD. sshd answers before AD does, so the plan waits for port 9389, then for `Get-ADDomain` and a query through the global catalog.
4. `dc1` points its DNS at itself and makes the OUs.
5. While `dc1` adds the users and the groups, `dc2`, `srv1` and `srv2` point their DNS at `dc1` and join with `LAB\azadmin`. Each reboots, and `srv1` and `srv2` land in `OU=Servers,OU=Lab`.
6. `dc2` is promoted to a domain controller, reboots, and waits for AD.
7. The domain admin's first password, and each member's local one, are replaced with ones nobody knows.

## What to know

- **You log in the same way afterwards.** `ssh azadmin@<ip>` works on all four. On the DCs that's now the domain's `LAB\azadmin`, a Domain Admin. On the members it's still the local `azadmin`.
- **State holds secrets of Azure's making.** `azurerm` keeps each VM's first admin password and the extensions' settings in state, host private keys included. That's why this example encrypts state. The others join with `dc1`'s first password, which promotion made the domain admin's, and the last step replaces it, so the copy in state stops being useful. The host keys stay useful, so treat state as a secret.
- **Conn3x keeps its own passwords out.** `dsrm_password` and `user_passwords` are ephemeral, and Conn3x's steps never put a password in plan or state.
- **The second plan is empty right after apply.** Hours later it may not be. Windows updates Defender on its own, and when that leaves a reboot pending, a plan shows a DC's reboot step again. That's `only_if_pending` doing its job.
- **SSH is the only way in,** from `admin_cidrs` only. RDP stays closed, and the VMs reach each other only inside their network.
- **It's a lab.** AD's files stay on the OS disk, and the DSRM password is the same on both DCs. Removing a step doesn't demote a DC or take a server out of the domain: delete the VMs for that.
