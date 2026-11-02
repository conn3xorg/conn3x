param($A)
$out = @{ kind = 'missing'; link_on_way = ''; sids = @{} }
foreach ($p in @($A.principals)) {
  if (-not $p) { continue }
  try {
    if ($p -match '^S-1-[0-9-]+$') { $out.sids[$p] = ([Security.Principal.SecurityIdentifier]$p).Value }
    else { $out.sids[$p] = ([Security.Principal.NTAccount]$p).Translate([Security.Principal.SecurityIdentifier]).Value }
  } catch { $out.sids[$p] = '' }
}
# A folder on the way that's a link means the path isn't the one configured.
$at = [string]$A.path
while ($at) {
  $parent = [IO.Path]::GetDirectoryName($at)
  if (-not $parent) { break }
  $d = Get-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
  if ($d -and ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $out.link_on_way = $parent; return $out }
  $at = $parent
}
try { $i = Get-Item -LiteralPath $A.path -Force -ErrorAction Stop }
catch [Management.Automation.ItemNotFoundException] { return $out }
$out.kind = if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { 'link' } elseif ($i.PSIsContainer) { 'directory' } else { 'file' }
if ($out.kind -eq 'link') { return $out }
if ($out.kind -eq 'file' -and $A.hash) { $out.sha256 = (Get-FileHash -LiteralPath $A.path -Algorithm SHA256).Hash }
$acl = Get-Acl -LiteralPath $A.path
$out.protected = [bool]$acl.AreAccessRulesProtected
$out.owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
$out.entries = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
  @{ sid = $_.IdentityReference.Value; mask = [int]$_.FileSystemRights; allow = ([string]$_.AccessControlType -eq 'Allow');
     flags = [int]$_.InheritanceFlags; only = [int]$_.PropagationFlags; inherited = [bool]$_.IsInherited }
})
$out
