param($A)
$store = 'Cert:\' + $A.location + '\' + $A.store
if ($A.drop) {
  $thumb = [string]$A.thumbprint
  if (-not $thumb -and (Test-Path -LiteralPath $A.path -PathType Leaf) -and -not $A.pfx) {
    $thumb = ([Security.Cryptography.X509Certificates.X509Certificate2]::new([string]$A.path)).Thumbprint
  }
  if ($thumb -and (Test-Path -LiteralPath "$store\$thumb")) { Remove-Item -LiteralPath "$store\$thumb" -Force -ErrorAction Stop }
  return @{ thumbprint = $thumb }
}
if (-not (Test-Path -LiteralPath $A.path -PathType Leaf)) { throw "$($A.path) isn't a file on this host; copy it there first, with a windows_file step" }
if ($A.pfx) {
  $pw = New-Object Security.SecureString
  foreach ($ch in ([string]$A.password).ToCharArray()) { $pw.AppendChar($ch) }
  $certs = @(Import-PfxCertificate -FilePath $A.path -CertStoreLocation $store -Password $pw -Exportable:$false -ErrorAction Stop)
  # A PFX can bring its chain: the one with the private key is the server's.
  $leaf = @($certs | Where-Object { $_.HasPrivateKey })[0]
  if (-not $leaf) { $leaf = $certs[0] }
} else {
  $leaf = @(Import-Certificate -FilePath $A.path -CertStoreLocation $store -ErrorAction Stop)[0]
}
@{ thumbprint = [string]$leaf.Thumbprint; sha256 = (Get-FileHash -LiteralPath $A.path -Algorithm SHA256).Hash.ToLowerInvariant() }
