param($A)
$PSModuleAutoLoadingPreference = 'None'
# Without its AD: drive the module loads faster, and reaches for nothing else.
$env:ADPS_LoadDefaultDrive = 0
# Only a domain controller: elsewhere a key login has no domain credentials.
Import-Module CimCmdlets
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { return @{ ad = $false } }
# The stub stops on any error, so a DC without the module lands in catch.
try { Import-Module ActiveDirectory } catch { return @{ ad = $false } }
$out = @{ ad = $true; exists = $false; path_dn = ''; wanted = @{}; members = @() }
if ($A.path) {
  try { $out.path_dn = [string](Get-ADObject -Identity ([string]$A.path)).DistinguishedName }
  catch { if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { throw } }
}
foreach ($m in @($A.members)) {
  if (-not $m) { continue }
  # LDAP filter escapes, the backslash first.
  $e = ([string]$m) -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
  $o = @(Get-ADObject -LDAPFilter "(sAMAccountName=$e)")
  $out.wanted[[string]$m] = if ($o.Count) { [string]$o[0].DistinguishedName } else { '' }
}
$e = ([string]$A.name) -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
$g = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$e)" -Properties Description, member)
if (-not $g.Count) { return $out }
$g = $g[0]
$out.exists = $true
$out.dn = [string]$g.DistinguishedName
# Everything after the first comma that isn't escaped.
$out.parent = $out.dn -replace '^(?:\\.|[^\\,])+,', ''
$out.sid = [string]$g.SID.Value
$out.scope = [string]$g.GroupScope
$out.category = [string]$g.GroupCategory
$out.description = [string]$g.Description
$out.members = @($g.member | ForEach-Object { [string]$_ })
$out
