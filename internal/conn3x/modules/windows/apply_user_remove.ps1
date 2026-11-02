param($A)
$u = Get-LocalUser -Name $A.name -ErrorAction SilentlyContinue
if ($u) { Remove-LocalUser -InputObject $u }
