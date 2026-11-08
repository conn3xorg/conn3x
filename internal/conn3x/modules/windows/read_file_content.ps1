param($A)
# A file's bytes, for import only: Conn3x otherwise reads just a hash. A link
# at the path or on the way, or anything over max bytes, returns nothing.
$at = [string]$A.path
while ($at) {
  $parent = [IO.Path]::GetDirectoryName($at)
  if (-not $parent) { break }
  $d = Get-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
  if ($d -and ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return @{ ok = $false; why = 'a folder on the way to it is a link' } }
  $at = $parent
}
$i = Get-Item -LiteralPath $A.path -Force -ErrorAction Stop
if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { return @{ ok = $false; why = 'it is a link' } }
if ($i.PSIsContainer) { return @{ ok = $false; why = 'it is a folder' } }
if ($i.Length -gt [long]$A.max) { return @{ ok = $false; why = ('it is ' + $i.Length + ' bytes, over the ' + $A.max + ' an import reads') } }
@{ ok = $true; content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($A.path)) }
