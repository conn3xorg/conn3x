param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include safepath
$path = $A.path
Assert-FullName $path
$dir = [IO.Path]::GetDirectoryName($path)
# A drive has no folder above it to open it from.
if ($dir) { Lock-Folders $dir -Strict; $h = Open-In ([IO.Path]::GetFileName($path)) 0x20081 3 } else { $h = Open-NoFollow $path 0x20081 3 }
if (-not $h) { throw "$path doesn't exist" }
[void]$script:held.Add($h)
$i = Get-Info $h
Assert-NotLink $path $i
$isDir = [bool]($i.Attributes -band 0x10)
if (-not $isDir -and $i.Links -gt 1) { throw "$path has other hard links, whose access this would change" }
Set-Rules $h $isDir $A.entries ([bool]$A.exact) $A.inherit $A.owner
