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
$out = @{ ad = $true; exists = $false; path_dn = ''; wanted = @{}; members = @() }
if ($A.path) {
  try { $out.path_dn = [string](Get-ADObject -Server 'localhost' -Identity ([string]$A.path)).DistinguishedName }
  catch { if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { throw } }
}
# LDAP filter escapes, the backslash first.
$e = ([string]$A.name) -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
$g = @(Get-ADGroup -Server 'localhost' -LDAPFilter "(sAMAccountName=$e)" -Properties Description, member)
# The tables' keys ignore case, as sAMAccountName does, so each answer lands
# on the name as configured.
$names = @(@($A.members) | Where-Object { $_ } | ForEach-Object { [string]$_ })
foreach ($m in $names) { $out.wanted[$m] = '' }
$known = @{}
if ($g.Count) {
  # Those already in the group come back in one paged LDAP query to this DC,
  # as another may not have the latest yet. One query a member took 85s for
  # 5,001 members on Azure, near the read's deadline, and reading the AD
  # cmdlets' objects in a loop that size took 29s more.
  $dn = ([string]$g[0].DistinguishedName) -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
  $ds = [DirectoryServices.DirectorySearcher]::new([adsi]'LDAP://localhost', "(memberOf=$dn)", [string[]]@('sAMAccountName', 'distinguishedName'))
  $ds.PageSize = 1000
  $found = $ds.FindAll()
  try {
    foreach ($r in $found) {
      $sam = $r.Properties['samaccountname']
      if ($sam.Count) { $known[[string]$sam[0]] = [string]$r.Properties['distinguishedname'][0] }
    }
  } finally { $found.Dispose() }
}
foreach ($m in $names) { if ($known[$m]) { $out.wanted[$m] = $known[$m] } }
# The others, 50 to a query: a long OR is slow for AD to answer.
$rest = @($names | Where-Object { -not $known[$_] })
for ($i = 0; $i -lt $rest.Count; $i += 50) {
  $f = (@($rest | Select-Object -Skip $i -First 50) | ForEach-Object { '(sAMAccountName=' + ($_ -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29') + ')' }) -join ''
  foreach ($o in @(Get-ADObject -Server 'localhost' -LDAPFilter "(|$f)" -Properties sAMAccountName)) { $out.wanted[[string]$o.sAMAccountName] = [string]$o.DistinguishedName }
}
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
