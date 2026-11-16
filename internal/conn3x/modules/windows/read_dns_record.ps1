param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$r = @{ zone = $false; values = @(); ttl = 0 }
$zone = Get-DnsServerZone -Name $A.zone -ErrorAction SilentlyContinue
if (-not $zone) { return $r }
$r.zone = $true
$records = @(Get-DnsServerResourceRecord -ZoneName $A.zone -Name $A.name -RRType $A.type -ErrorAction SilentlyContinue)
foreach ($rec in $records) {
  $d = $rec.RecordData
  $v = switch ($A.type) {
    'A' { [string]$d.IPv4Address }
    'AAAA' { [string]$d.IPv6Address }
    'CNAME' { [string]$d.HostNameAlias }
    'PTR' { [string]$d.PtrDomainName }
    'TXT' { [string]$d.DescriptiveText }
  }
  $r.values += $v
  $r.ttl = [int]$rec.TimeToLive.TotalSeconds
}
$r
