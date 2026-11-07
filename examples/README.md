# Examples

| Example | What it shows | Needs |
| --- | --- | --- |
| [try-it-locally](try-it-locally) | Plan, apply, a clean second plan, and drift, against a throwaway container | Podman or Docker |
| [secrets](secrets) | A password on the host and an HMAC in state, with `content_wo` and a write-only template | Podman or Docker |
| [digitalocean](digitalocean) | Three droplets created and configured in one plan, with pinned host keys | A DigitalOcean account |
| [azure-windows-server](azure-windows-server) | Experimental. A Windows Server VM created and configured in one plan | An Azure subscription |
| [azure-domain](azure-domain) | Experimental. A new Active Directory domain and a server joined to it, from one plan | An Azure subscription |

Each one runs with the [latest release](https://github.com/conn3xorg/conn3x/releases/latest). CI checks that every example validates.
