param($A)
Import-Module NetTCPIP, DnsClient
# The same choice of interface as read_dns_client.ps1.
if ($A.interface) {
  $i = Get-DnsClientServerAddress -InterfaceAlias $A.interface -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $i) { throw "no network interface named $($A.interface)" }
  $index = $i.InterfaceIndex
} else {
  $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property @{ Expression = { [int]$_.RouteMetric + [int]$_.InterfaceMetric } }, InterfaceIndex | Select-Object -First 1
  if (-not $route) { throw 'no interface has an IPv4 default route; name one with interface' }
  $index = $route.InterfaceIndex
}
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses ([string[]]$A.servers)
