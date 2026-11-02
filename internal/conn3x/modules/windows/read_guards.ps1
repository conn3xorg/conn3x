param($A)
if ($A.creates -and -not (Test-Path -LiteralPath $A.creates)) { return $false }
if ($A.removes -and (Test-Path -LiteralPath $A.removes)) { return $false }
$true
