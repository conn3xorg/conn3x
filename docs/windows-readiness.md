# Windows modules: what each needs before it leaves experimental

Each `windows_*` module starts out experimental. That's honest, but it's also a reason teams won't try them, so this page says what "ready" means and where each module stands. All 25 modules meet every point and have left experimental. A new module starts out experimental and joins the table with what it still needs. Pick a gap, and the linked issue says how to close it.

## What "ready" means

A module drops the experimental label when all of these hold:

1. **CI on both supported versions.** Its runner test passes on Windows Server 2022 and 2025. The `windows-host` job in `.github/workflows/windows.yml` runs on both since #568.
2. **A real circuit has used it.** It's in an Azure example or test, or someone has reported running it on their own servers.
3. **`import` works**, so a team can adopt what a server already has (#417).
4. **No open bug** labelled `windows` against it.
5. **Its page is complete:** what it does, an example, how removal works.

## Where each module stands

"Runner" is `test/windows/`, against GitHub-hosted Windows Server 2022 and 2025 runners. "Azure" is an `examples/azure-*` config or `test/azure/`, run against real Windows Server 2025 VMs. "Import" is whether `import` on a step can adopt what a server already has; "n/a" is a module that does something rather than owning something, so there's nothing to adopt.

| Module | Ready | Runner | Azure | Import | What's missing |
| --- | --- | --- | --- | --- | --- |
| `windows_acl` | yes | yes | yes | yes | |
| `windows_ad_domain` | yes | module-level: a child or a tree refused at its folder checks changes nothing and leaks no password | yes, through `azure-ad-child-domain`, a new tree beside it (#763), and `import` of both on their domain controllers | yes | |
| `windows_ad_domain_controller` | yes | module-level: a promotion refused at its folder checks changes nothing and leaks no password | yes, through `azure-ad-lab`, and from a workgroup server (#395) | yes | |
| `windows_ad_forest` | yes | yes | yes, and `import` on `azure-ad-lab`'s first domain controller | yes | |
| `windows_ad_group` | yes | module-level | yes, including scope and category changes (#408), 5,000 members (#407), members across a two-way forest trust (#621) and the lockout guard's global-catalog lookup (#622) | yes | |
| `windows_ad_ou` | yes | module-level | yes, and `import` on `azure-ad-lab`'s domain controller | yes | |
| `windows_ad_user` | yes | module-level | yes, and `import` on `azure-ad-lab`'s domain controller | yes | |
| `windows_directory` | yes | yes | yes | yes | |
| `windows_dns_client` | yes | yes | yes | yes | |
| `windows_domain_membership` | yes | module-level: a failed join changes nothing and leaks no password | yes, including `ou` (#396) and a 2022 host (#394) | yes | |
| `windows_feature` | yes | yes | yes | yes | |
| `windows_file` | yes | yes | yes | yes | |
| `windows_firewall_rule` | yes | yes | yes, through `azure-windows-fleet` | yes | |
| `windows_group` | yes | yes | yes, on an `azure-ad-lab` member server, with a domain user as a member | yes | |
| `windows_iis_app_pool` | yes | yes | yes, through `azure-windows-fleet` | yes | |
| `windows_iis_site` | yes | yes | yes, through `azure-windows-fleet` | yes | |
| `windows_package` | yes | yes | yes, through `azure-windows-fleet` | yes | |
| `windows_powershell` | yes | yes | yes | n/a | |
| `windows_reboot` | yes | yes | yes | n/a | |
| `windows_registry_value` | yes | yes | yes | yes | |
| `windows_scheduled_task` | yes | yes | yes, through `azure-windows-fleet` | yes | |
| `windows_service` | yes | yes | yes | yes | |
| `windows_update` | yes | reads only: an install on the runner is slow and pointless | yes, and an 8-month-behind Windows Server 2022 brought current with its cumulative and .NET updates (#583) | n/a | |
| `windows_user` | yes | yes | yes, on an `azure-ad-lab` member server | yes | |
| `windows_wait_for` | yes | yes | yes | n/a | |

"Module-level" means the runner test drives the module's Go API, not a circuit step: for `windows_ad_group` on a real domain controller, and for the domain controller and membership modules on a workgroup runner, where a change can't succeed, since it needs a domain and a reboot. Those two show that a refused or failed change leaves the host as it was and keeps the passwords out of the error; `azure-ad-lab` runs the change itself.

## What's left across the board

- **`import`**: twenty-one modules import now, every one that owns something. `windows_ad_domain`'s has been tried only in unit tests, not on a real child domain.

Windows Server 2022 runs in CI since #568, on the first try for every runner test.

Testers with their own Windows servers help with everything in the "Azure" column and with #351 and #464.
