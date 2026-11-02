param($A)
$g = Get-LocalGroup -Name $A.name -ErrorAction SilentlyContinue
if ($g) { Remove-LocalGroup -InputObject $g }
