param($A)
#include safepath
#include ad
$missing = Test-ADFolders @($A.database_path, $A.log_path, $A.sysvol_path)
if (-not (Get-Module -ListAvailable -Name ADDSDeployment)) {
  throw 'AD DS is not installed. Add a windows_feature step for AD-Domain-Services with include_management_tools = true'
}
Import-Module ADDSDeployment
New-ADFolders $missing
# The password becomes a SecureString through .NET, never through a cmdlet, as
# in apply_user.ps1: a logging policy shows a SecureString only by its type.
$set = @{
  DomainName                    = [string]$A.domain_name
  SafeModeAdministratorPassword = [Net.NetworkCredential]::new('', [string]$A.password).SecurePassword
}
if ($A.netbios_name) { $set.DomainNetbiosName = [string]$A.netbios_name }
if ($A.database_path) { $set.DatabasePath = [string]$A.database_path }
if ($A.log_path) { $set.LogPath = [string]$A.log_path }
if ($A.sysvol_path) { $set.SysvolPath = [string]$A.sysvol_path }
# Never a reboot: that's its own step, so it shows in the plan.
$r = Install-ADDSForest @set -InstallDns -NoRebootOnCompletion -Force -Confirm:$false -WarningAction SilentlyContinue
if ([string]$r.Status -ne 'Success') { throw "Install-ADDSForest: $($r.Status): $($r.Message)" }
Set-RebootMarker
@{ restart = $true }
