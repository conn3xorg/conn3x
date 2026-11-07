param($A)
#include ad
Import-AD
if ($A.create) {
  # Splatted: AD's Path parameter takes a distinguished name, not a file path.
  $set = @{ Name = [string]$A.name; Path = [string]$A.path }
  if ($A.description) { $set.Description = [string]$A.description }
  # Unset, Windows protects a new OU from accidental deletion.
  if ($null -ne $A.protected) { $set.ProtectedFromAccidentalDeletion = [bool]$A.protected }
  New-ADOrganizationalUnit @set
  return
}
$dn = [string]$A.dn
Set-ADText $dn description $A.description
if ($null -ne $A.protected) { Set-ADOrganizationalUnit -Identity $dn -ProtectedFromAccidentalDeletion ([bool]$A.protected) }
