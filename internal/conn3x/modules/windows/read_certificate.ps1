param($A)
$r = @{ in_store = $false; has_key = $false; file_exists = $false; file_sha256 = '' }
if ($A.thumbprint) {
  $at = 'Cert:\' + $A.location + '\' + $A.store + '\' + $A.thumbprint
  if (Test-Path -LiteralPath $at) {
    $r.in_store = $true
    $r.has_key = [bool](Get-Item -LiteralPath $at).HasPrivateKey
  }
}
if (Test-Path -LiteralPath $A.path -PathType Leaf) {
  $r.file_exists = $true
  $r.file_sha256 = (Get-FileHash -LiteralPath $A.path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$r
