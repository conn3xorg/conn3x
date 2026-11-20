param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# Reads Chocolatey's files and runs nothing, so a plan runs no package code.
# lib, .chocolatey and the package's folders are refused if they're links,
# so a planted one can't point the read at another file. Of the package's
# folder in .chocolatey, only .pin is looked at: .arguments beside it holds
# the install arguments, which can carry secrets.
$out = @{ chocolatey = $false; installed = $false; version = ''; pinned = $false }
$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
if (-not $root -or -not (Test-Path -LiteralPath ($root + '\choco.exe') -PathType Leaf)) { return $out }
$out.chocolatey = $true
function Get-Plain($path) {
  $i = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  if ($i -and ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "$path is a link, and Conn3x doesn't follow links in Chocolatey's folders" }
  $i
}
$lib = Get-Plain ($root + '\lib')
if (-not $lib) { return $out }
# NTFS finds the folder whatever case the name is in, and it has the
# package's own case.
$pkg = Get-Plain ($lib.FullName + '\' + $A.name)
if (-not $pkg -or -not $pkg.PSIsContainer) { return $out }
$nuspec = Get-Plain ($pkg.FullName + '\' + $pkg.Name + '.nuspec')
if (-not $nuspec) { return $out }
# A package's own XML: no DTD, and nothing fetched.
$settings = [Xml.XmlReaderSettings]@{ DtdProcessing = [Xml.DtdProcessing]::Prohibit; XmlResolver = $null }
$reader = [Xml.XmlReader]::Create($nuspec.FullName, $settings)
try {
  if ($reader.ReadToFollowing('version')) { $out.version = $reader.ReadElementContentAsString() -replace '^\s+|\s+$', '' }
} finally { $reader.Dispose() }
if (-not $out.version) { throw "$($nuspec.FullName) has no version" }
$out.installed = $true
$state = Get-Plain ($root + '\.chocolatey')
if ($state) {
  $dir = Get-Plain ($state.FullName + '\' + $pkg.Name + '.' + $out.version)
  if ($dir) { $out.pinned = [bool](Get-Plain ($dir.FullName + '\.pin')) }
}
$out
