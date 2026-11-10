# An Active Directory domain on Azure

**Experimental.** Windows support is new and may change between releases.

You want a domain to test against, and building one by hand means two RDP sessions, a wizard, a reboot, a DNS change and another reboot. This does all of it from one plan. Two Windows Server 2025 VMs come up: `dc1` becomes the first domain controller of `lab.conn3x.test`, and `win2` points its DNS at `dc1` and joins. Then the domain gets something to hold: an OU, a user and a group she's in. Every reboot is a step you can see in the plan.

## Run it

You need an Azure subscription, `az login`, an SSH key, and room for 4 vCPUs in the region. It costs about $0.22 an hour while it's up, for two `Standard_B2s_v2` VMs in `westus2` with their disks and IPs, so destroy it when you're done.

```sh
export TF_VAR_state_passphrase="$(openssl rand -hex 16)"   # keep this; state needs it
export TF_VAR_dsrm_password="a long password of your own" # never in plan or state
export TF_VAR_alice_password="another one, for alice"     # never in plan or state
export TF_VAR_admin_cidrs="[\"$(curl -4 -s https://ifconfig.me)/32\"]"
export TF_VAR_admin_public_key_file=~/.ssh/id_ed25519.pub
export TF_VAR_admin_private_key_file=~/.ssh/id_ed25519

conn3x init
conn3x plan -out tfplan
conn3x apply tfplan
```

The first apply takes about 13 minutes. Run `conn3x plan` again and it reports no changes. Windows keeps updating Defender on its own, though, and when that leaves a reboot pending, a later plan shows `dc1`'s reboot step again. That's `only_if_pending` doing its job.

```sh
conn3x destroy
```

## What happens, in order

1. Both VMs boot, and the bootstrap installs each one's host key.
2. `dc1` gets the AD DS role, becomes the forest's first domain controller, reboots, and waits until Active Directory answers. sshd comes back before AD does, so the plan waits for port 9389 and then for `Get-ADDomain`.
3. `dc1` makes the `Lab` OU, the user `alice` in it with your password, the group `LabAdmins` with `alice` in it, and `join`, an ordinary account for adding computers to the domain.
4. `win2` waits for AD to answer, points its DNS at `dc1`, joins with `LAB\join`, and reboots.
5. Each VM's first password is replaced with one nobody knows.

## What to know

- **You log in the same way afterwards.** `ssh azadmin@<ip>` works on both. On `dc1` that's now the domain's `LAB\azadmin`, a Domain Admin. On `win2` it's still the local `azadmin`.
- **State holds secrets of Azure's making.** `azurerm` keeps each VM's first admin password and the extensions' settings in state, host private keys included. That's why this example encrypts state. Promotion made `dc1`'s first password the domain admin's, and the last step replaces it, so the copy in state stops being useful. The host keys stay useful, so treat state as a secret.
- **The domain admin's password never leaves `dc1`.** A join hands the joining server a domain account's password, so `win2` gets one that can do little: `join` is an ordinary user, and Active Directory lets any user add up to ten computers. Its password is random and stays in the encrypted state. For more than ten computers, delegate "create computer objects" on an OU to an account like it instead of reaching for an admin.
- **The DSRM password never reaches state.** `dsrm_password` is ephemeral, and Conn3x's own steps keep every password out of plan and state.
- **Hand changes show up.** Change `alice`'s name in Active Directory Users and Computers, or take her out of `LabAdmins`, and `conn3x drift` exits 2 and names the step. `conn3x apply` puts it back.
- **SSH is the only way in,** from `admin_cidrs` only. RDP stays closed, and the VMs reach each other only inside their network. The domain controller still has a public address, which is how you and Conn3x reach it. A domain you keep belongs behind a bastion or a VPN, with no public address at all.
- **Windows doesn't patch itself here.** `patch_mode = "Manual"` and `automatic_updates_enabled = false` keep a surprise reboot out of the middle of an apply. That's right for an hour of testing and wrong for anything you keep: turn updates back on, or patch with `windows_update` steps.
- **AD's files stay on the OS disk.** For a domain you'd keep, Microsoft advises a data disk with host caching off for the database and SYSVOL; set `database_path`, `log_path` and `sysvol_path` on the forest step.
- **Removing a step doesn't undo it.** Conn3x never demotes a domain controller or takes a host out of a domain. Destroy the VMs for that.
