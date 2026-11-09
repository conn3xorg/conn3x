param($A)
$PSModuleAutoLoadingPreference = 'None'
# Without its AD: drive the module loads faster, and reaches for nothing else.
$env:ADPS_LoadDefaultDrive = 0
# Only a domain controller: elsewhere a key login has no domain credentials.
Import-Module CimCmdlets
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { return @{ ad = $false } }
# The stub stops on any error, so a DC without the module lands in catch.
try { Import-Module ActiveDirectory } catch { return @{ ad = $false } }
# -Server 'localhost' asks this DC, not one the locator picks that may lag.
$out = @{ ad = $true; exists = $false; base = '' }
try {
  if ($A.path) { $out.base = (Get-ADObject -Server 'localhost' -Identity ([string]$A.path)).DistinguishedName } else { $out.base = (Get-ADDomain -Server 'localhost').DistinguishedName }
} catch { if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { throw } ; return $out }
# The name holds nothing an LDAP filter would read as syntax; Go checks it.
$ou = @(Get-ADOrganizationalUnit -Server 'localhost' -LDAPFilter "(ou=$([string]$A.name))" -SearchBase $out.base -SearchScope OneLevel -Properties Description, ProtectedFromAccidentalDeletion)
if (-not $ou.Count) { return $out }
$out.exists = $true
$out.dn = [string]$ou[0].DistinguishedName
$out.description = [string]$ou[0].Description
$out.protected = [bool]$ou[0].ProtectedFromAccidentalDeletion
$out
