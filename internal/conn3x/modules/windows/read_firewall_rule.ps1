param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module NetSecurity
# The name was checked for wildcards before it got here.
$r = @(Get-NetFirewallRule -Name $A.name -ErrorAction SilentlyContinue)
if ($r.Count -eq 0) { return @{ exists = $false } }
$rule = $r[0]
$port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
$addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
@{ exists = $true; display_name = [string]$rule.DisplayName; description = [string]$rule.Description
   direction = [string]$rule.Direction; action = [string]$rule.Action; enabled = ([string]$rule.Enabled -eq 'True')
   profile = [int]$rule.Profile; protocol = [string]$port.Protocol
   local_ports = @($port.LocalPort | ForEach-Object { [string]$_ }); remote_addresses = @($addr.RemoteAddress | ForEach-Object { [string]$_ }) }
