# expect: use -LiteralPath, not -Path
param($A)
Remove-Item -Path $A.path
