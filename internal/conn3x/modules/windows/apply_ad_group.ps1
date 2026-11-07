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
    foreach ($m in @($A.remove)) {
      if ($m -and $mine -contains (Get-ADObject -Identity ([string]$m) -Properties objectSid).objectSid.Value) { throw "this would take $m out of $($g.Name), and the login Conn3x uses gets its rights through it; that could lock Conn3x out" }
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
if ($add.Count) { Add-ADGroupMember -Identity $dn -Members $add }
if ($remove.Count) { Remove-ADGroupMember -Identity $dn -Members $remove -Confirm:$false }
