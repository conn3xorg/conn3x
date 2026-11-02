# expect: set a property of something
param($A)
$f = Get-Item -LiteralPath $A.a
$f.IsReadOnly = $true
