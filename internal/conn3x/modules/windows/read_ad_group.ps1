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
# on the name as configured. A name with a domain, DOMAIN\name or a UPN, is
# for an account elsewhere in the forest, or in a domain it trusts.
$all = @(@($A.members) | Where-Object { $_ } | ForEach-Object { [string]$_ })
$names = @($all | Where-Object { $_ -notmatch '[\\@]' })
foreach ($m in $all) { $out.wanted[$m] = @{ dn = ''; sid = '' } }
$known = @{}
# Each member's SID by DN, for the members this DC holds.
$sidOf = @{}
if ($g.Count) {
  # Those already in the group come back in one paged LDAP query to this DC,
  # as another may not have the latest yet. One query a member took 85s for
  # 5,001 members on Azure, near the read's deadline, and reading the AD
  # cmdlets' objects in a loop that size took 29s more.
  $dn = ([string]$g[0].DistinguishedName) -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
  $ds = [DirectoryServices.DirectorySearcher]::new([adsi]'LDAP://localhost', "(memberOf=$dn)", [string[]]@('sAMAccountName', 'distinguishedName', 'objectSid'))
  $ds.PageSize = 1000
  $found = $ds.FindAll()
  try {
    foreach ($r in $found) {
      $p = @{ dn = [string]$r.Properties['distinguishedname'][0]; sid = '' }
      if ($r.Properties['objectsid'].Count) { $p.sid = [string][Security.Principal.SecurityIdentifier]::new([byte[]]$r.Properties['objectsid'][0], 0).Value }
      $sidOf[$p.dn] = $p.sid
      $sam = $r.Properties['samaccountname']
      if ($sam.Count) { $known[[string]$sam[0]] = $p }
    }
  } finally { $found.Dispose() }
}
foreach ($m in $names) { if ($known[$m]) { $out.wanted[$m] = $known[$m] } }
# The others, 50 to a query: a long OR is slow for AD to answer.
$rest = @($names | Where-Object { -not $known[$_] })
for ($i = 0; $i -lt $rest.Count; $i += 50) {
  $f = (@($rest | Select-Object -Skip $i -First 50) | ForEach-Object { '(sAMAccountName=' + ($_ -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29') + ')' }) -join ''
  foreach ($o in @(Get-ADObject -Server 'localhost' -LDAPFilter "(|$f)" -Properties sAMAccountName, objectSid)) {
    $out.wanted[[string]$o.sAMAccountName] = @{ dn = [string]$o.DistinguishedName; sid = [string]$o.objectSid.Value }
  }
}
# The global catalog has every account in the forest: it gives the DN of an
# account in another domain, and the SID of a member this DC doesn't hold.
$gc = [DirectoryServices.DirectorySearcher]::new([adsi]'GC://localhost', '(objectClass=*)', [string[]]@('distinguishedName', 'objectSid'))
$gc.PageSize = 1000
# A name with a domain is looked up as Windows does at logon, so one in a
# trusted domain resolves too, and one nobody has stays empty.
# shortcut: one lookup and one GC query per such name, fine for tens to a
# few hundred; batch them if groups list thousands from other domains.
foreach ($m in @($all | Where-Object { $_ -match '[\\@]' })) {
  try { $sid = [string][Security.Principal.NTAccount]::new($m).Translate([Security.Principal.SecurityIdentifier]).Value }
  catch {
    if ($_.Exception -is [Security.Principal.IdentityNotMappedException] -or $_.Exception.InnerException -is [Security.Principal.IdentityNotMappedException]) { continue }
    throw
  }
  $p = @{ dn = ''; sid = $sid }
  # AD takes a SID's text in an objectSid filter. Seen on Azure on Server
  # 2025: this search found a child-domain user, where binding GC:// to
  # <SID=...> returned nothing. One outside the forest isn't in the global
  # catalog, and keeps only its SID.
  $gc.Filter = "(objectSid=$sid)"
  $found = $gc.FindAll()
  try { foreach ($r in $found) { $p.dn = [string]$r.Properties['distinguishedname'][0] } } finally { $found.Dispose() }
  $out.wanted[$m] = $p
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
# Members from other domains in the forest aren't under this DC's domain,
# so the search above missed them. The global catalog has them, 50 to a query.
$dns = @($g.member | ForEach-Object { [string]$_ })
$other = @($dns | Where-Object { $null -eq $sidOf[$_] })
for ($i = 0; $i -lt $other.Count; $i += 50) {
  $gc.Filter = '(|' + ((@($other | Select-Object -Skip $i -First 50) | ForEach-Object { '(distinguishedName=' + ($_ -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29') + ')' }) -join '') + ')'
  $found = $gc.FindAll()
  try {
    foreach ($r in $found) {
      if ($r.Properties['objectsid'].Count) { $sidOf[[string]$r.Properties['distinguishedname'][0]] = [string][Security.Principal.SecurityIdentifier]::new([byte[]]$r.Properties['objectsid'][0], 0).Value }
    }
  } finally { $found.Dispose() }
}
# Every member that has a SID needs it, or the comparison would match one
# by SID and the other by DN. So any still without one is looked up by
# itself; one AD can't find stops the read rather than guess.
foreach ($d in @($dns | Where-Object { -not $sidOf[$_] })) {
  $o = Get-ADObject -Server 'localhost:3268' -Identity $d -Properties objectSid
  $sidOf[$d] = if ($o.objectSid) { [string]$o.objectSid.Value } else { '' }
}
$out.members = @($dns | ForEach-Object { @{ dn = $_; sid = [string]$sidOf[$_] } })
$out
