param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# A text file's bytes, for an edit step to compare against, as
# read_file_content.ps1 reads them for import: a link at the path or on the
# way, a folder, or anything over max bytes returns nothing but why. Only a
# file that isn't there is missing, which an edit with create may make: any
# other error, such as access denied, fails the read rather than pass for
# missing, so create can never replace a file it couldn't see.
$at = [string]$A.path
while ($at) {
  $parent = [IO.Path]::GetDirectoryName($at)
  if (-not $parent) { break }
  try { $d = Get-Item -LiteralPath $parent -Force -ErrorAction Stop }
  catch [Management.Automation.ItemNotFoundException] { $d = $null }
  if ($d -and ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return @{ ok = $false; why = 'a folder on the way to it is a link' } }
  $at = $parent
}
try { $i = Get-Item -LiteralPath $A.path -Force -ErrorAction Stop }
catch [Management.Automation.ItemNotFoundException] { return @{ ok = $true; exists = $false } }
if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { return @{ ok = $false; why = 'it is a link' } }
if ($i.PSIsContainer) { return @{ ok = $false; why = 'it is a folder' } }
if ($i.Length -gt [long]$A.max) { return @{ ok = $false; why = ('it is ' + $i.Length + ' bytes, over the ' + $A.max + ' an edit reads') } }
@{ ok = $true; exists = $true; content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($A.path)) }
