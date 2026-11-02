param($A)
$r = @(Get-NetFirewallRule -Name $A.name -ErrorAction SilentlyContinue)
if ($r.Count) { Remove-NetFirewallRule -InputObject $r[0] }
