# expect: Set-Item isn't on the list
param($A)
Set-Item -LiteralPath $A.path -Value 1
