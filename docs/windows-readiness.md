# Windows modules: what each needs before it leaves experimental

Every `windows_*` module is marked experimental. That's honest, but it's also a reason teams won't try them, so this page says what "ready" means and where each module stands. Pick a gap, and the linked issue says how to close it.

## What "ready" means

A module drops the experimental label when all of these hold:

1. **CI on both supported versions.** Its runner test passes on Windows Server 2022 and 2025. The `windows-host` job in `.github/workflows/windows.yml` runs on both since #568.
2. **A real circuit has used it.** It's in an Azure example or test, or someone has reported running it on their own servers.
3. **`import` works**, so a team can adopt what a server already has (#417).
4. **No open bug** labelled `windows` against it.
5. **Its page is complete:** what it does, an example, how removal works.

## Where each module stands

"Runner" is `test/windows/`, against GitHub-hosted Windows Server 2022 and 2025 runners. "Azure" is an `examples/azure-*` config or `test/azure/`, run against real Windows Server 2025 VMs. "Import" is whether `import` on a step can adopt what a server already has; "n/a" is a module that does something rather than owning something, so there's nothing to adopt.

| Module | Runner | Azure | Import | What's missing |
| --- | --- | --- | --- | --- |
| `windows_acl` | no | yes | no | A runner test (#561) |
| `windows_ad_domain_controller` | no | yes, through `azure-ad-lab` | no | Promoting straight from a workgroup server is untested (#395) |
| `windows_ad_forest` | yes | yes | no | |
| `windows_ad_group` | module-level | yes | no | Members from another domain (#462); changing scope or category on a real DC (#408); groups of 5,000+ (#407) |
| `windows_ad_ou` | module-level | yes | no | |
| `windows_ad_user` | module-level | yes | no | |
| `windows_directory` | yes | yes | yes | |
| `windows_dns_client` | yes | yes | no | |
| `windows_domain_membership` | no | yes | no | The `ou` argument (#396); joining a 2022 host (#394) |
| `windows_feature` | yes | yes | yes | |
| `windows_file` | yes | yes | yes | |
| `windows_firewall_rule` | yes | yes, through `azure-windows-fleet` | no | |
| `windows_group` | yes | no | yes | An Azure run |
| `windows_iis_app_pool` | yes | yes, through `azure-windows-fleet` | no | |
| `windows_iis_site` | yes | yes, through `azure-windows-fleet` | no | |
| `windows_package` | yes | yes, through `azure-windows-fleet` | no | |
| `windows_powershell` | yes | yes | n/a | |
| `windows_reboot` | yes | yes | n/a | |
| `windows_registry_value` | no | yes | yes | A runner test (#561) |
| `windows_scheduled_task` | yes | yes, through `azure-windows-fleet` | no | |
| `windows_service` | no | yes | yes | A runner test (#561) |
| `windows_update` | no | run by hand once | n/a | A runner test (#561); a large cumulative update on a real host |
| `windows_user` | yes | no | yes | An Azure run |
| `windows_wait_for` | yes | yes | n/a | |

"Module-level" means the runner test drives the module's Go API on a real domain controller, not a circuit step.

## What's left across the board

- **`import` on the rest** (#417): seven modules import now (#563, #567). `windows_package` is next, then the less common ones.

Windows Server 2022 runs in CI since #568, on the first try for every runner test.

Testers with their own Windows servers help with everything in the "Azure" column and with #351, #394, #395 and #464.
