param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# Accounts compare by SID, so Administrators and BUILTIN\Administrators are
# one. A name that doesn't resolve gets "".
$want = @{}
foreach ($n in @($A.accounts)) {
  if (-not $n) { continue }
  $sid = ''
  try { $sid = ([Security.Principal.NTAccount]::new($n)).Translate([Security.Principal.SecurityIdentifier]).ToString() } catch { }
  $want[$n] = $sid
}
$share = Get-SmbShare -Name $A.name -ErrorAction SilentlyContinue
if (-not $share) { return @{ exists = $false; sids = $want } }
$access = @()
foreach ($e in @(Get-SmbShareAccess -Name $A.name -ErrorAction Stop)) {
  $sid = ''
  try { $sid = ([Security.Principal.NTAccount]::new([string]$e.AccountName)).Translate([Security.Principal.SecurityIdentifier]).ToString() } catch { }
  $access += @{ account = [string]$e.AccountName; sid = $sid; right = [string]$e.AccessRight; type = [string]$e.AccessControlType }
}
@{ exists = $true; path = [string]$share.Path; description = [string]$share.Description; access = $access; sids = $want }
