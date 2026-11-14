param($A)
# Accounts compare by SID, so Administrators and BUILTIN\Administrators are one.
function Sid($name) {
  try { ([Security.Principal.NTAccount]::new($name)).Translate([Security.Principal.SecurityIdentifier]).ToString() } catch { '' }
}
$want = @{}
foreach ($n in @($A.accounts)) { if ($n) { $want[$n] = Sid $n } }
$share = Get-SmbShare -Name $A.name -ErrorAction SilentlyContinue
if (-not $share) { return @{ exists = $false; sids = $want } }
$access = @()
foreach ($e in @(Get-SmbShareAccess -Name $A.name -ErrorAction Stop)) {
  $access += @{ account = [string]$e.AccountName; sid = (Sid ([string]$e.AccountName)); right = [string]$e.AccessRight; type = [string]$e.AccessControlType }
}
@{ exists = $true; path = [string]$share.Path; description = [string]$share.Description; access = $access; sids = $want }
