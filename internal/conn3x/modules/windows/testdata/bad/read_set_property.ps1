# expect: set a property of something
param($A)
(Get-Item -LiteralPath $A.a).IsReadOnly = $true
