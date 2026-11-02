param($A)
# Taking the login out of a group it's in, such as Administrators, could lock
# Conn3x out, whether it's a member itself or through another group, such as
# Domain Admins. So in a group the login belongs to, none of the login's own
# SIDs is removed.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$mine = @($id.User.Value) + @($id.Groups | ForEach-Object { $_.Value })
$g = Get-LocalGroup -Name $A.name -ErrorAction SilentlyContinue
if ($g -and $mine -contains $g.SID.Value) {
  foreach ($s in @($A.remove)) {
    if ($mine -contains $s) { throw "this would take $s out of $($g.Name), and the login Conn3x uses gets its rights through it; that could lock Conn3x out" }
  }
}
if ($A.create) {
  $new = @{}
  if ($null -ne $A.description) { $new.Description = [string]$A.description }
  $g = New-LocalGroup -Name $A.name @new
} else {
  if ($null -ne $A.description -and $g.Description -cne $A.description) { Set-LocalGroup -InputObject $g -Description ([string]$A.description) }
}
foreach ($s in @($A.add)) { if ($s) { Add-LocalGroupMember -Group $g -Member ([string]$s) } }
foreach ($s in @($A.remove)) { if ($s) { Remove-LocalGroupMember -Group $g -Member ([string]$s) } }
