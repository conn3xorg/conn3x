# expect: use -LiteralPath, not -Path
param($A)
Remove-Item -Pa $A.path
