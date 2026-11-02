param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module Microsoft.PowerShell.LocalAccounts
$out = @{ exists = $false; sids = @{}; members = @() }
foreach ($p in @($A.principals)) {
  if (-not $p) { continue }
  try {
    if ($p -match '^S-1-[0-9-]+$') { $out.sids[$p] = ([Security.Principal.SecurityIdentifier]$p).Value }
    else { $out.sids[$p] = ([Security.Principal.NTAccount]$p).Translate([Security.Principal.SecurityIdentifier]).Value }
  } catch { $out.sids[$p] = '' }
}
$g = Get-LocalGroup -Name $A.name -ErrorAction SilentlyContinue
if (-not $g) { return $out }
$out.exists = $true
$out.description = [string]$g.Description
$out.members = @(Get-LocalGroupMember -Group $g | ForEach-Object { $_.SID.Value })
$out
