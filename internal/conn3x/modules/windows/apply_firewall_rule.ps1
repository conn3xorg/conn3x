param($A)
$set = @{
  DisplayName = [string]$A.display_name; Direction = [string]$A.direction; Action = [string]$A.action
  Protocol = [string]$A.protocol; Enabled = $(if ($A.enabled) { 'True' } else { 'False' })
  LocalPort = $(if (@($A.local_ports).Count) { [string[]]@($A.local_ports) } else { 'Any' })
  RemoteAddress = $(if (@($A.remote_addresses).Count) { [string[]]@($A.remote_addresses) } else { 'Any' })
  Profile = $(if (@($A.profiles).Count) { [string]::Join(',', [string[]]@($A.profiles)) } else { 'Any' })
}
if ($null -ne $A.description) { $set.Description = [string]$A.description }
# The name was checked for wildcards before it got here.
$r = @(Get-NetFirewallRule -Name $A.name -ErrorAction SilentlyContinue)
if ($r.Count) {
  # On Set, -DisplayName picks rules; -NewDisplayName renames one.
  $set.NewDisplayName = $set.DisplayName
  $set.Remove('DisplayName')
  Set-NetFirewallRule -InputObject $r[0] @set
}
else { New-NetFirewallRule -Name $A.name @set | Out-Null }
