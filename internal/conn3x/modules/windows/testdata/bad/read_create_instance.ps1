# expect: method Create isn't on the list
param($A)
(Get-Item -LiteralPath $A.a).Create()
