param($A)
Import-Module ServerManager
# Never -Restart: reboots are their own step, so they show in the plan.
if ($A.present) {
  $r = Install-WindowsFeature -Name $A.name -IncludeAllSubFeature:([bool]$A.sub_features) -IncludeManagementTools:([bool]$A.management_tools)
} else {
  $r = Uninstall-WindowsFeature -Name $A.name
}
if (-not $r.Success) { throw "changing feature $($A.name) failed with $($r.ExitCode)" }
@{ restart = ([string]$r.RestartNeeded -eq 'Yes') }
