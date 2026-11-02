param($A)
# Taking the login out of a group, such as Administrators, could lock Conn3x out.
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if (@($A.remove) -contains $me) { throw "this would take the login Conn3x uses ($me) out of the group" }
if ($A.create) {
  $new = @{}
  if ($null -ne $A.description) { $new.Description = [string]$A.description }
  $g = New-LocalGroup -Name $A.name @new
} else {
  $g = Get-LocalGroup -Name $A.name
  if ($null -ne $A.description -and $g.Description -cne $A.description) { Set-LocalGroup -InputObject $g -Description ([string]$A.description) }
}
foreach ($s in @($A.add)) { if ($s) { Add-LocalGroupMember -Group $g -Member ([string]$s) } }
foreach ($s in @($A.remove)) { if ($s) { Remove-LocalGroupMember -Group $g -Member ([string]$s) } }
