param($A)
$PSModuleAutoLoadingPreference = 'None'
# Without its AD: drive the module loads faster, and reaches for nothing else.
$env:ADPS_LoadDefaultDrive = 0
# Only a domain controller: elsewhere a key login has no domain credentials.
Import-Module CimCmdlets
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { return @{ ad = $false } }
# The stub stops on any error, so a DC without the module lands in catch.
try { Import-Module ActiveDirectory } catch { return @{ ad = $false } }
$out = @{ ad = $true; exists = $false; path_dn = '' }
if ($A.path) {
  try { $out.path_dn = [string](Get-ADObject -Identity ([string]$A.path)).DistinguishedName }
  catch { if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { throw } }
}
# As read_ad_group.ps1.
$n = ([string]$A.name) -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
$u = @(Get-ADUser -LDAPFilter "(sAMAccountName=$n)" -Properties Description, DisplayName, PasswordNeverExpires, PasswordLastSet)
if (-not $u.Count) { return $out }
$u = $u[0]
$out.exists = $true
$out.dn = [string]$u.DistinguishedName
$out.parent = $out.dn -replace '^(?:\\.|[^\\,])+,', ''
$out.sid = [string]$u.SID.Value
$out.upn = [string]$u.UserPrincipalName
$out.given_name = [string]$u.GivenName
$out.surname = [string]$u.Surname
$out.display_name = [string]$u.DisplayName
$out.description = [string]$u.Description
$out.enabled = [bool]$u.Enabled
$out.password_never_expires = [bool]$u.PasswordNeverExpires
$out.password_set = ($null -ne $u.PasswordLastSet)
$out
