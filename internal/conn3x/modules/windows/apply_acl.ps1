param($A)
#include safepath
$path = $A.path
if ([IO.Path]::GetDirectoryName($path)) { Lock-Folders ([IO.Path]::GetDirectoryName($path)) -Strict }
$h = Hold-Path $path
if (-not $h) { throw "$path doesn't exist" }
$i = Get-Info $h
Assert-NotLink $path $i
$isDir = [bool]($i.Attributes -band 0x10)
if (-not $isDir -and $i.Links -gt 1) { throw "$path has other hard links, whose access this would change" }
Set-Rules $path $isDir $A.entries ([bool]$A.exact) $A.inherit $A.owner
