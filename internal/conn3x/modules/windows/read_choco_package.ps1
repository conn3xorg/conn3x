param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# Reads Chocolatey's files and runs nothing, so a plan runs no package code.
# lib, .chocolatey and the package's folders and files are refused if
# they're links, before anything in them is read, so a planted one can't
# point the read at another file. Of the package's folder in .chocolatey,
# only .pin is looked at: .arguments beside it holds the install
# arguments, which can carry secrets.
$out = @{ chocolatey = $false; installed = $false; version = ''; pinned = $false }
$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
if (-not $root -or -not (Test-Path -LiteralPath ($root + '\choco.exe') -PathType Leaf)) { return $out }
$out.chocolatey = $true
$lib = Get-Item -LiteralPath ($root + '\lib') -Force -ErrorAction SilentlyContinue
if (-not $lib) { return $out }
# NTFS finds the folder whatever case the name is in, and it has the
# package's own case.
$pkg = Get-Item -LiteralPath ($lib.FullName + '\' + $A.name) -Force -ErrorAction SilentlyContinue
if (-not $pkg -or -not $pkg.PSIsContainer) { return $out }
$nuspec = Get-Item -LiteralPath ($pkg.FullName + '\' + $pkg.Name + '.nuspec') -Force -ErrorAction SilentlyContinue
foreach ($i in @($lib, $pkg, $nuspec) | Where-Object { $_ }) {
  if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($i.FullName) is a link, and Conn3x doesn't follow links in Chocolatey's folders" }
}
if (-not $nuspec) { return $out }
# A package's own XML: no DTD, and nothing fetched.
$settings = [Xml.XmlReaderSettings]@{ DtdProcessing = [Xml.DtdProcessing]::Prohibit; XmlResolver = $null }
$reader = [Xml.XmlReader]::Create($nuspec.FullName, $settings)
try {
  if ($reader.ReadToFollowing('version')) { $out.version = $reader.ReadElementContentAsString() -replace '^\s+|\s+$', '' }
} finally { $reader.Dispose() }
if (-not $out.version) { throw "$($nuspec.FullName) has no version" }
$out.installed = $true
$state = Get-Item -LiteralPath ($root + '\.chocolatey') -Force -ErrorAction SilentlyContinue
$dir = if ($state) { Get-Item -LiteralPath ($state.FullName + '\' + $pkg.Name + '.' + $out.version) -Force -ErrorAction SilentlyContinue }
$pin = if ($dir) { Get-Item -LiteralPath ($dir.FullName + '\.pin') -Force -ErrorAction SilentlyContinue }
foreach ($i in @($state, $dir, $pin) | Where-Object { $_ }) {
  if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($i.FullName) is a link, and Conn3x doesn't follow links in Chocolatey's folders" }
}
$out.pinned = [bool]$pin
$out
