param($A)
#include safepath
Lock-Folders ([IO.Path]::GetDirectoryName($A.path))
$i = Stat-Path $A.path
if (-not $i) { return }
if ($i.Attributes -band 0x10) { throw "$($A.path) is a folder" }
[IO.File]::Delete($A.path)
