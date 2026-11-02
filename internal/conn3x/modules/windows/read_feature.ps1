param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module ServerManager
$f = Get-WindowsFeature -Name $A.name
if (-not $f) { return @{ exists = $false } }
@{ exists = $true; state = [string]$f.InstallState; installed = [bool]$f.Installed }
