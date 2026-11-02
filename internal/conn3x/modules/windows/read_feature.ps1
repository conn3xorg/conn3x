param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module ServerManager
$f = Get-WindowsFeature -Name $A.name
if (-not $f) { return @{ exists = $false } }
$missing = @()
# Only Windows knows what these options add, and -WhatIf asks it without changing anything.
if ($f.Installed -and ($A.sub_features -or $A.management_tools)) {
  $would = Install-WindowsFeature -Name $A.name -IncludeAllSubFeature:([bool]$A.sub_features) -IncludeManagementTools:([bool]$A.management_tools) -WhatIf
  $missing = @($would.FeatureResult | ForEach-Object { [string]$_.Name })
}
@{ exists = $true; state = [string]$f.InstallState; installed = [bool]$f.Installed; missing = $missing }
