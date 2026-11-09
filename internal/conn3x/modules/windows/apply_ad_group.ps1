param($A)
#include ad
Import-AD
$mine = Get-LoginSIDs
if ($A.create) {
  $set = @{ Name = [string]$A.name; SamAccountName = [string]$A.name; GroupScope = 'Global'; GroupCategory = 'Security' }
  if ($A.scope) { $set.GroupScope = [string]$A.scope }
  if ($A.category) { $set.GroupCategory = [string]$A.category }
  # Splatted: AD's Path parameter takes a distinguished name, not a file path.
  if ($A.path) { $set.Path = [string]$A.path }
  if ($A.description) { $set.Description = [string]$A.description }
  $dn = (New-ADGroup @set -PassThru).DistinguishedName
} else {
  $dn = [string]$A.dn
  $g = Get-ADGroup -Identity $dn
  # Taking the login out of a group it gets its rights through, such as Domain
  # Admins, could lock Conn3x out, so none of its own SIDs is removed.
  if ($mine -contains $g.SID.Value) {
    $sids = @($A.remove_sids)
    for ($i = 0; $i -lt $sids.Count; $i++) {
      # Without a SID from the read, ask the global catalog, so the guard fails
      # closed: a member AD can't find stops the apply here.
      $sid = [string]$sids[$i]
      if (-not $sid) { $sid = [string](Get-ADObject -Server 'localhost:3268' -Identity ([string]@($A.remove)[$i]) -Properties objectSid).objectSid.Value }
      if ($sid -and $mine -contains $sid) { throw "this would take $(@($A.remove)[$i]) out of $($g.Name), and the login Conn3x uses gets its rights through it; that could lock Conn3x out" }
    }
  }
  if ($A.scope -and [string]$g.GroupScope -ne $A.scope) {
    # Global and DomainLocal only change into each other through Universal.
    if ([string]$g.GroupScope -ne 'Universal' -and $A.scope -ne 'universal') { Set-ADGroup -Identity $dn -GroupScope Universal }
    Set-ADGroup -Identity $dn -GroupScope ([string]$A.scope)
  }
  if ($A.category -and [string]$g.GroupCategory -ne $A.category) { Set-ADGroup -Identity $dn -GroupCategory ([string]$A.category) }
  Set-ADText $dn description $A.description
  if ($A.move) { $dn = (Move-ADObject -Identity $dn -TargetPath ([string]$A.path) -PassThru).DistinguishedName }
}
$add = @(@($A.add) | Where-Object { $_ } | ForEach-Object { [string]$_ })
$remove = @(@($A.remove) | Where-Object { $_ } | ForEach-Object { [string]$_ })
if ($add.Count -or $remove.Count) {
  # Straight to this DC over LDAP, bound by GUID so the DN needs no escaping.
  # A member added as <SID=...> may be in another domain of the forest, or in
  # one it trusts, where AD makes the foreign security principal itself. The
  # AD cmdlets look each member up in this domain only.
  $guid = (Get-ADGroup -Identity $dn).ObjectGUID
  $de = [adsi]"LDAP://localhost/<GUID=$guid>"
  try {
    # 3 appends values and 4 deletes them, without reading the whole list,
    # a thousand to a write so a big group's request stays small. Slices,
    # not Select-Object: COM can't take the wrapped strings that returns.
    for ($i = 0; $i -lt $add.Count; $i += 1000) { $de.PutEx(3, 'member', [object[]]$add[$i..([Math]::Min($i + 999, $add.Count - 1))]); $de.SetInfo() }
    for ($i = 0; $i -lt $remove.Count; $i += 1000) { $de.PutEx(4, 'member', [object[]]$remove[$i..([Math]::Min($i + 999, $remove.Count - 1))]); $de.SetInfo() }
  } finally { $de.psbase.Dispose() }
}
