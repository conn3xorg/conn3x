param($A)
#include ad
Import-AD
$ou = Get-ADOrganizationalUnit -Identity ([string]$A.dn) -Properties ProtectedFromAccidentalDeletion
if ($ou.ProtectedFromAccidentalDeletion) { throw "$($ou.DistinguishedName) is protected from accidental deletion; set protected = false and apply before removing the step" }
# Never recursive: what's inside may not be Conn3x's to delete.
if (@(Get-ADObject -SearchBase $ou.DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=*)' -ResultSetSize 1).Count) { throw "$($ou.DistinguishedName) isn't empty; move or delete what's in it first" }
Remove-ADOrganizationalUnit -Identity $ou -Confirm:$false
