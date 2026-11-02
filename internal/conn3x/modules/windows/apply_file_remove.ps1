param($A)
#include safepath
Assert-FullName $A.path
Lock-Folders ([IO.Path]::GetDirectoryName($A.path))
$i = Stat-Path $A.path
if (-not $i) { return }
$isLink = $i.Attributes -band 0x400
if (($i.Attributes -band 0x10) -and -not $isLink) { throw "$($A.path) is a folder" }
# A link goes, not what it points to. Removing a junction leaves its target alone.
if ($i.Attributes -band 0x10) { [IO.Directory]::Delete($A.path) } else { [IO.File]::Delete($A.path) }
