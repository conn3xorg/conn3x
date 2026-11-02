# Windows Server on Azure

**Experimental.** Windows support is new and may change between releases.

One plan makes a Windows Server 2025 VM on Azure and configures it: IIS, a registry value, a locked-down folder, a config file, a secret that never reaches state, and a reboot only if Windows asks for one. Conn3x installs its own host key at first boot, so it checks the host from the very first connection.

## Run it

You need an Azure subscription, `az login`, and an SSH key. It costs about $0.11 an hour for each hour it's up on `Standard_B2s_v2` in `westus2`, including the disk and the IP, so destroy it when you're done.

```sh
export TF_VAR_state_passphrase="$(openssl rand -hex 16)"   # keep this; state needs it
export TF_VAR_app_secret="something private"
export TF_VAR_admin_cidrs="[\"$(curl -4 -s https://ifconfig.me)/32\"]"
export TF_VAR_admin_public_key_file=~/.ssh/id_ed25519.pub
export TF_VAR_admin_private_key_file=~/.ssh/id_ed25519

conn3x init
conn3x plan -out tfplan
conn3x apply tfplan
```

The first apply takes about 12 minutes. Run `conn3x plan` again and it reports no changes. Change something on the host by hand, and `conn3x drift` exits 2 and names it; `conn3x apply` puts it back.

```sh
conn3x destroy
```

## What to know

- **State holds secrets of Azure's making.** `azurerm` keeps the first admin password and the extension's settings in state, including the host's private key. That's why this example encrypts state. The last step replaces the password, so the copy in state stops being useful. The host key stays useful, so treat state as a secret.
- **SSH is the only way in,** from `admin_cidrs` only. RDP stays closed, and password login is off.
- **Destroying removes the VM and everything in its resource group.**
- **Removing a step doesn't undo it on the host.** Destroy the VM for that.
