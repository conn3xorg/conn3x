param($A)
# The password becomes a SecureString through .NET, never through a cmdlet:
# a logging policy can record a cmdlet's parameters, but shows a SecureString
# only by its type name.
$p = $null
if ($null -ne $A.password) { $p = [Net.NetworkCredential]::new('', [string]$A.password).SecurePassword }
$set = @{}
if ($null -ne $A.full_name) { $set.FullName = [string]$A.full_name }
if ($null -ne $A.description) { $set.Description = [string]$A.description }
if ($A.create) {
  if ($p) { $set.Password = $p } else { $set.NoPassword = $true }
  # Made disabled when asked, so it's never briefly enabled.
  if ($A.disabled) { $set.Disabled = $true }
  $u = New-LocalUser -Name $A.name @set
} else {
  $u = Get-LocalUser -Name $A.name
  if ($p) { $set.Password = $p }
  if ($set.Count) { Set-LocalUser -InputObject $u @set }
}
# After the password, so an account is never enabled before it has one.
if ($null -ne $A.disabled) {
  if ($A.disabled) { Disable-LocalUser -InputObject $u } else { Enable-LocalUser -InputObject $u }
}
