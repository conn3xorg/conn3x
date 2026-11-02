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
$out.members = @(try { Get-LocalGroupMember -Group $g | ForEach-Object { $_.SID.Value } }
catch {
  # Get-LocalGroupMember fails on a member whose SID no longer resolves (error
  # 1789), as a deleted domain or Entra account leaves behind. ADSI lists those.
  ([ADSI]('WinNT://./' + $g.Name + ',group')).Invoke('Members') | ForEach-Object {
    [Security.Principal.SecurityIdentifier]::new([byte[]]$_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null), 0).Value
  }
})
$out
