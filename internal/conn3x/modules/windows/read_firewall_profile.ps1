param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$PSModuleAutoLoadingPreference = 'None'
Import-Module NetSecurity
# The profile's own settings, as Set-NetFirewallProfile sets them.
$p = Get-NetFirewallProfile -Name $A.name
$out = @{ enabled = [string]$p.Enabled; inbound = [string]$p.DefaultInboundAction; outbound = [string]$p.DefaultOutboundAction }
if (-not $A.rules) { return $out }

# For the lockout check: every enabled inbound rule in force, Group Policy's
# included, with its filters, joined by instance ID in one pass each.
$ports = @{}; Get-NetFirewallPortFilter -All -PolicyStore ActiveStore | ForEach-Object { $ports[$_.InstanceID] = $_ }
$addrs = @{}; Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore | ForEach-Object { $addrs[$_.InstanceID] = $_ }
$apps = @{}; Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore | ForEach-Object { $apps[$_.InstanceID] = $_ }
$svcs = @{}; Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore | ForEach-Object { $svcs[$_.InstanceID] = $_ }
Import-Module CimCmdlets
$sshd = [string](Get-CimInstance Win32_Service -Filter "Name='sshd'").PathName
$sshd = $sshd -replace '^\s*"?|"?\s*$', ''
$out.rules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -PolicyStore ActiveStore | ForEach-Object {
  $id = $_.InstanceID
  $program = [string]$apps[$id].Program
  $service = [string]$svcs[$id].Service
  @{ name = [string]$_.Name; action = [string]$_.Action; profile = [int]$_.Profile
     protocol = [string]$ports[$id].Protocol
     local_ports = @($ports[$id].LocalPort | ForEach-Object { [string]$_ })
     remote_addresses = @($addrs[$id].RemoteAddress | ForEach-Object { [string]$_ })
     # A rule for one program or service lets in, or blocks, only that one.
     sshd_program = ($program -eq '' -or $program -eq 'Any' -or ($sshd -and [Environment]::ExpandEnvironmentVariables($program) -eq $sshd))
     sshd_service = ($service -eq '' -or $service -eq 'Any' -or $service -eq 'sshd') }
})
# The profile of the interface the SSH connection came in on: a change to
# another profile can't cut it off.
if ($A.client) {
  Import-Module NetTCPIP
  $c = Get-NetTCPConnection -State Established -LocalPort $A.port -RemoteAddress $A.client -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($c) {
    $ip = Get-NetIPAddress -IPAddress $c.LocalAddress -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ip) {
      Import-Module NetConnection
      $cp = Get-NetConnectionProfile -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($cp) { $out.conn_profile = [string]$cp.NetworkCategory }
    }
  }
}
$out
