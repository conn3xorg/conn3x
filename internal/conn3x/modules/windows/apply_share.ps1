param($A)
# Not $A.remove: when the key is missing, that's the hashtable's own Remove
# method, which is truthy.
if ($A.drop) {
  if (Get-SmbShare -Name $A.name -ErrorAction SilentlyContinue) { Remove-SmbShare -Name $A.name -Force -ErrorAction Stop }
  return
}
$share = Get-SmbShare -Name $A.name -ErrorAction SilentlyContinue
if (-not $share) {
  if (-not (Test-Path -LiteralPath $A.path -PathType Container)) { throw "$($A.path) isn't a folder on this host; make it first, with a windows_directory step" }
  $new = @{ Name = $A.name; Path = $A.path; ErrorAction = 'Stop' }
  if ($null -ne $A.description) { $new.Description = $A.description }
  # Read for Everyone is New-SmbShare's own default; the lists below replace it.
  $null = New-SmbShare @new
  if (-not (Get-SmbShare -Name $A.name -ErrorAction SilentlyContinue)) { throw "New-SmbShare didn't make share $($A.name) on $($A.path)" }
} elseif ($null -ne $A.description -and $share.Description -ne $A.description) {
  Set-SmbShare -Name $A.name -Description $A.description -Force -ErrorAction Stop
}
foreach ($g in @($A.grant)) {
  if ($g) { $null = Grant-SmbShareAccess -Name $A.name -AccountName $g.account -AccessRight $g.right -Force -ErrorAction Stop }
}
foreach ($r in @($A.revoke)) {
  if ($r) { $null = Revoke-SmbShareAccess -Name $A.name -AccountName $r -Force -ErrorAction Stop }
}
