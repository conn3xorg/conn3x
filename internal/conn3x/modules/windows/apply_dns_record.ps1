param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
if (-not (Get-DnsServerZone -Name $A.zone -ErrorAction SilentlyContinue)) { throw "this server has no DNS zone $($A.zone); run the step on the zone's DNS server, usually a domain controller" }
$ttl = [TimeSpan]::FromSeconds([int]$A.ttl)
foreach ($v in @($A.remove_values)) {
  if (-not $v) { continue }
  $old = @(Get-DnsServerResourceRecord -ZoneName $A.zone -Name $A.name -RRType $A.type -ErrorAction SilentlyContinue | Where-Object {
    $d = $_.RecordData
    $have = switch ($A.type) { 'A' { [string]$d.IPv4Address } 'AAAA' { [string]$d.IPv6Address } 'CNAME' { [string]$d.HostNameAlias } 'PTR' { [string]$d.PtrDomainName } 'TXT' { [string]$d.DescriptiveText } }
    $have -eq $v
  })
  foreach ($o in $old) { Remove-DnsServerResourceRecord -ZoneName $A.zone -InputObject $o -Force -ErrorAction Stop }
}
foreach ($v in @($A.add_values)) {
  if (-not $v) { continue }
  $add = @{ ZoneName = $A.zone; Name = $A.name; TimeToLive = $ttl; ErrorAction = 'Stop' }
  switch ($A.type) {
    'A' { Add-DnsServerResourceRecordA @add -IPv4Address $v }
    'AAAA' { Add-DnsServerResourceRecordAAAA @add -IPv6Address $v }
    'CNAME' { Add-DnsServerResourceRecordCName @add -HostNameAlias $v }
    'PTR' { Add-DnsServerResourceRecordPtr @add -PtrDomainName $v }
    'TXT' { Add-DnsServerResourceRecord @add -Txt -DescriptiveText $v }
  }
}
if ($A.set_ttl) {
  foreach ($o in @(Get-DnsServerResourceRecord -ZoneName $A.zone -Name $A.name -RRType $A.type -ErrorAction SilentlyContinue)) {
    if ([int]$o.TimeToLive.TotalSeconds -ne [int]$A.ttl) {
      $new = $o.Clone()
      $new.TimeToLive = $ttl
      Set-DnsServerResourceRecord -ZoneName $A.zone -OldInputObject $o -NewInputObject $new -ErrorAction Stop
    }
  }
}
