# expect: use -LiteralPath with Test-Path
param($A)
Test-Path $A.path
