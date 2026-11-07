param($A)
#include safepath
#include ad
$missing = Test-ADFolders @($A.database_path, $A.log_path, $A.sysvol_path)
if (-not (Get-Module -ListAvailable -Name ADDSDeployment)) {
  throw 'AD DS is not installed. Add a windows_feature step for AD-Domain-Services with include_management_tools = true'
}
Import-Module ADDSDeployment
New-ADFolders $missing
# Both passwords become SecureStrings through .NET, as in apply_ad_forest.ps1.
# A key login has no credentials of its own to reach the domain with, so the
# account to promote with is given explicitly.
$set = @{
  DomainName                    = [string]$A.domain_name
  Credential                    = [Management.Automation.PSCredential]::new([string]$A.username, [Net.NetworkCredential]::new('', [string]$A.password).SecurePassword)
  SafeModeAdministratorPassword = [Net.NetworkCredential]::new('', [string]$A.safe_mode_password).SecurePassword
}
if ($A.database_path) { $set.DatabasePath = [string]$A.database_path }
if ($A.log_path) { $set.LogPath = [string]$A.log_path }
if ($A.sysvol_path) { $set.SysvolPath = [string]$A.sysvol_path }
# Never a reboot: that's its own step, so it shows in the plan.
$r = Install-ADDSDomainController @set -InstallDns -NoRebootOnCompletion -Force -Confirm:$false -WarningAction SilentlyContinue
if ([string]$r.Status -ne 'Success') { throw "Install-ADDSDomainController: $($r.Status): $($r.Message)" }
Set-RebootMarker
@{ restart = $true }
