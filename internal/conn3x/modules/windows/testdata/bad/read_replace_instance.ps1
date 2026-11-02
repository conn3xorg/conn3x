# expect: Replace only on the text
param($A)
(Get-Item -LiteralPath $A.a).Replace($A.b, $null)
