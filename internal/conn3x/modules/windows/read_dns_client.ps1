param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module NetTCPIP, DnsClient
# Azure NICs can show two adapters that are up, so with no name the one with the
# IPv4 default route is used, as in read_facts.ps1.
$all = @()
if ($A.interface) {
  $all = @(Get-DnsClientServerAddress -InterfaceAlias $A.interface -ErrorAction SilentlyContinue)
} else {
  $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
  if ($route) { $all = @(Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue) }
}
if (-not $all.Count) { return @{ found = $false } }
# AddressFamily: 2 is IPv4, 23 is IPv6.
@{ found = $true; index = [int]$all[0].InterfaceIndex; alias = [string]$all[0].InterfaceAlias
   ipv4 = @($all | Where-Object { [int]$_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
   ipv6 = @($all | Where-Object { [int]$_.AddressFamily -eq 23 } | ForEach-Object { $_.ServerAddresses }) }
