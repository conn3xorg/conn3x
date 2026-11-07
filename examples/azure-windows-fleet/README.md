# A Windows fleet on Azure

**Experimental.** Windows support is new and may change between releases.

Five web servers that should be identical rarely are. One got IIS by hand, one by a script someone ran twice, one never got the firewall rule. This example builds the whole set from one config: a domain controller, five member servers joined to it, and the same IIS baseline on all five in one apply. Change one by hand afterwards and `conn3x drift` names that one host.

Six Windows Server 2025 VMs come up:

| VM | Address | Role |
| --- | --- | --- |
| `dc1` | `10.47.0.4` | Makes the forest `fleet.conn3x.test` and the OUs `Fleet` and `Fleet/Web` |
| `web1` to `web5` | `10.47.0.5` to `10.47.0.9` | Join the domain into `OU=Web,OU=Fleet`, then get IIS |

Every web server gets [circuit-iis](https://github.com/conn3xorg/circuit-iis): IIS and static content, a site called `fleet` with its own app pool, a page, a Windows Firewall rule for port 80, and an app pool recycle every night at 03:00. The domain comes from [circuit-active-directory](https://github.com/conn3xorg/circuit-active-directory).

## What it costs

Six `Standard_B2s_v2` VMs in `westus2`, with their disks and IPs, cost about $0.66 an hour. A run from nothing, with the checks and the delete, took about 35 minutes, so about 40 cents. Delete it when you're done: left up, it's about $16 a day.

It needs 12 vCPUs in the region, and a new pay-as-you-go subscription often has exactly 12 for the B-series. `az vm list-usage -l westus2 -o table` shows yours. Set `web_servers` to fewer than 5 to use less: each one is 2 vCPUs.

## Run it

You need an Azure subscription, `az login`, Conn3x v0.8.0 or later, and an SSH key.

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

The plan has 120 resources. The apply took 21 minutes in both our runs, and the second plan said `No changes.`

## Where the time goes

| From | To | What |
| --- | --- | --- |
| 0:00 | 6:40 | Azure makes the six VMs, and the bootstrap installs each host key |
| 6:40 | 13:50 | `dc1` installs AD DS, makes the forest, reboots and waits for AD, then makes the OUs |
| 13:50 | 15:50 | All five web servers join at once, and each reboots |
| 15:50 | 20:50 | IIS goes onto all five at once |

The web servers really do run side by side: the IIS feature install started on all five within 6 seconds, and the last step finished on all five within a second. What sets the pace is the slowest host. A circuit runs each step on every host before any host starts the next one, so when `web1` had IIS installed after 3 minutes, it waited 90 seconds for `web5` before the next step.

## Check it

```sh
ssh azadmin@$(conn3x output -json ips | jq -r .web3) powershell "(Invoke-WebRequest -UseBasicParsing http://localhost/).StatusCode"
ssh azadmin@$(conn3x output -json ips | jq -r .web3) powershell Test-ComputerSecureChannel
```

Each web server should say `200` and `True`.

## Catch drift on one host

Stop the site on one server, then ask Conn3x what changed:

```sh
ssh azadmin@$(conn3x output -json ips | jq -r .web3) powershell "Import-Module IISAdministration; Stop-IISSite -Name fleet -Confirm:\$false"
conn3x drift
```

`conn3x drift` exits 2 and names one resource, `module.iis.conn3x_windows_iis_site.iis__site["web3"]`. The other four aren't mentioned. `conn3x plan -out tfplan` and `conn3x apply tfplan` start it again.

## Tear it down

```sh
az group delete -n conn3x-windows-fleet --yes
az group list -o table
```

## What to know

- **Expect one round of reboots soon after.** For roughly the first half hour after the VMs are made, Windows services itself, even with automatic updates off: a Defender platform update (KB4052623) and Store app updates, which set the Component Based Servicing `RebootPending` flag. A plan in that window shows a reboot step for some or all hosts. Some flags clear on their own, so applying it reboots only the hosts that still need one, and the plan after that is empty. In our runs that was one or two of the six. Read the plan before you apply it.
- **You log in the same way afterwards.** `ssh azadmin@<ip>`. On `dc1` that's the domain's `FLEET\azadmin`. On the web servers it's still the local `azadmin`.
- **State holds secrets of Azure's making.** `azurerm` keeps each VM's first admin password and the extensions' settings, host private keys included, so this example encrypts state. The web servers join with `dc1`'s first password, and the last steps replace it and each local one, so those copies stop being useful. The host keys stay useful, so treat state as a secret.
- **SSH is the only way in,** from `admin_cidrs` only. Port 80 is open in Windows Firewall but not in the network security group, so the sites answer only inside the network.
- **It's a lab.** One domain controller, AD on the OS disk. Removing a step doesn't take a server out of the domain or uninstall IIS: delete the VMs for that.
