param($A)
$u = Get-LocalUser -Name $A.name -ErrorAction SilentlyContinue
if (-not $u) { return }
if ($u.SID.Value -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw "$($u.Name) is the user Conn3x logs in as; deleting it would lock Conn3x out of the host" }
Remove-LocalUser -InputObject $u
