param($A)
#include ad
Import-AD
# The password becomes a SecureString through .NET, never through a cmdlet:
# a logging policy can record a cmdlet's parameters, but shows a SecureString
# only by its type name.
$p = $null
if ($null -ne $A.password) { $p = [Net.NetworkCredential]::new('', [string]$A.password).SecurePassword }
$text = [ordered]@{ userPrincipalName = $A.upn; givenName = $A.given_name; sn = $A.surname; displayName = $A.display_name; description = $A.description }
if ($A.create) {
  # Made disabled, and enabled below once it has its password.
  $set = @{ Name = [string]$A.name; SamAccountName = [string]$A.name; Enabled = $false }
  # Splatted: AD's Path parameter takes a distinguished name, not a file path.
  if ($A.path) { $set.Path = [string]$A.path }
  $other = @{}
  foreach ($k in $text.Keys) { if ($text[$k]) { $other[$k] = [string]$text[$k] } }
  if ($other.Count) { $set.OtherAttributes = $other }
  if ($p) { $set.AccountPassword = $p }
  if ($null -ne $A.password_never_expires) { $set.PasswordNeverExpires = [bool]$A.password_never_expires }
  $u = New-ADUser @set -PassThru
} else {
  $u = Get-ADUser -Identity ([string]$A.dn)
  foreach ($k in $text.Keys) { Set-ADText $u.DistinguishedName $k $text[$k] }
  if ($p) { Set-ADAccountPassword -Identity $u -Reset -NewPassword $p }
  if ($null -ne $A.password_never_expires) { Set-ADUser -Identity $u -PasswordNeverExpires ([bool]$A.password_never_expires) }
  if ($A.move) { $u = Get-ADUser -Identity (Move-ADObject -Identity $u -TargetPath ([string]$A.path) -PassThru).DistinguishedName }
}
# After the password, so an account is never enabled before it has one.
if ($null -ne $A.enabled) {
  if ($A.enabled) { Enable-ADAccount -Identity $u.DistinguishedName }
  else {
    # Checked here too, by SID: the provider can't always see the login's name.
    if ($u.SID.Value -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw "$($u.Name) is the user Conn3x logs in as; disabling it would lock Conn3x out of the host" }
    Disable-ADAccount -Identity $u.DistinguishedName
  }
}
