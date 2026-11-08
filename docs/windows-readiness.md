# Windows modules: what each needs before it leaves experimental

Every `windows_*` module is marked experimental. That's honest, but it's also a reason teams won't try them, so this page says what "ready" means and where each module stands. Pick a gap, and the linked issue says how to close it.

## What "ready" means

A module drops the experimental label when all of these hold:

1. **CI on both supported versions.** Its runner test passes on Windows Server 2022 and 2025. Today the `windows-host` job in `.github/workflows/windows.yml` runs on `windows-2025` only.
2. **A real circuit has used it.** It's in an Azure example or test, or someone has reported running it on their own servers.
3. **`import` works**, so a team can adopt what a server already has (#417).
4. **No open bug** labelled `windows` against it.
5. **Its page is complete:** what it does, an example, how removal works.

## Where each module stands

"Runner" is `test/windows/`, against the GitHub-hosted Windows Server 2025 runner. "Azure" is an `examples/azure-*` config or `test/azure/`, run against real Windows Server 2025 VMs. Nothing has run on 2022 in CI yet, and no module supports `import`.

| Module | Runner | Azure | What's missing besides 2022 and import |
| --- | --- | --- | --- |
| `windows_acl` | no | yes | A runner test (#561) |
| `windows_ad_domain_controller` | no | yes, through `azure-ad-lab` | Promoting straight from a workgroup server is untested (#395) |
| `windows_ad_forest` | yes | yes | |
| `windows_ad_group` | module-level | yes | Members from another domain (#462); changing scope or category on a real DC (#408); groups of 5,000+ (#407) |
| `windows_ad_ou` | module-level | yes | |
| `windows_ad_user` | module-level | yes | |
| `windows_directory` | yes | yes | |
| `windows_dns_client` | yes | yes | |
| `windows_domain_membership` | no | yes | The `ou` argument (#396); joining a 2022 host (#394) |
| `windows_feature` | yes | yes | |
| `windows_file` | yes | yes | |
| `windows_firewall_rule` | yes | yes, through `azure-windows-fleet` | |
| `windows_group` | yes | no | An Azure run |
| `windows_iis_app_pool` | yes | yes, through `azure-windows-fleet` | |
| `windows_iis_site` | yes | yes, through `azure-windows-fleet` | |
| `windows_package` | yes | yes, through `azure-windows-fleet` | |
| `windows_powershell` | yes | yes | |
| `windows_reboot` | yes | yes | |
| `windows_registry_value` | no | yes | A runner test (#561) |
| `windows_scheduled_task` | yes | yes, through `azure-windows-fleet` | |
| `windows_service` | no | yes | A runner test (#561) |
| `windows_update` | no | run by hand once | A runner test (#561); a large cumulative update on a real host |
| `windows_user` | yes | no | An Azure run |
| `windows_wait_for` | yes | yes | |

"Module-level" means the runner test drives the module's Go API on a real domain controller, not a circuit step.

## The gaps that block everything

- **Windows Server 2022 in CI.** A `windows-2022` leg in the `windows-host` job covers every module at once (#560).
- **`import` on Windows** (#417). Without it, a team can't adopt servers they already run, which is the first thing an enterprise trial does.

Testers with their own Windows servers help with everything in the "Azure" column and with #351, #394, #395 and #464.
