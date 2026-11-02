param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module Microsoft.PowerShell.LocalAccounts
$u = Get-LocalUser -Name $A.name -ErrorAction SilentlyContinue
if (-not $u) { return @{ exists = $false } }
@{ exists = $true; sid = $u.SID.Value; full_name = [string]$u.FullName; description = [string]$u.Description
   enabled = [bool]$u.Enabled; password_set = ($null -ne $u.PasswordLastSet) }
