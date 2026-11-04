param($A)
#include safepath
# Folders for the database, logs and SYSVOL. On a new volume anyone may make a
# folder at the top and own it, or a junction to one, and AD keeps its secrets
# and every DC's logon scripts in these. So each must be admin-only, owned by a
# trusted account and no link, or missing, and then it's made admin-only here.
# The holds keep them all in place while Install-ADDSForest runs.
$missing = @()
foreach ($p in @(@($A.database_path, $A.log_path, $A.sysvol_path) | Where-Object { $_ } | Select-Object -Unique)) {
  Assert-PlainPath $p
  Lock-Folders ([IO.Path]::GetDirectoryName($p)) -Strict
  if (Stat-Path $p) {
    Assert-AdminOnly $p -Folder -Inherited -Runner 'Active Directory'
    # Held and admin-only now, so nothing new can appear; what's already
    # inside could belong to anyone, with rules of its own.
    if ([IO.Directory]::EnumerateFileSystemEntries($p).GetEnumerator().MoveNext()) { throw "$p isn't empty. Give Active Directory an empty folder, or one that doesn't exist yet." }
  } else { $missing += $p }
}
if (-not (Get-Module -ListAvailable -Name ADDSDeployment)) {
  throw 'AD DS is not installed. Add a windows_feature step for AD-Domain-Services with include_management_tools = true'
}
Import-Module ADDSDeployment
$admins = @(@{ principal = 'S-1-5-18'; mask = 0x1F01FF; flags = 3; allow = $true }, @{ principal = 'S-1-5-32-544'; mask = 0x1F01FF; flags = 3; allow = $true })
foreach ($p in $missing) { Lock-Folders $p -Create -Strict (New-Security ([Security.AccessControl.DirectorySecurity]) $admins) }
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
# As apply_package.ps1: a volatile key that windows_reboot's check finds, so a
# run that stops before its reboot step plans that reboot next time.
$parent = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Conn3x')
try {
  $k = $parent.CreateSubKey('RebootRequired', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Microsoft.Win32.RegistryOptions]::Volatile)
  $k.Close()
} finally { $parent.Close() }
@{ restart = $true }
