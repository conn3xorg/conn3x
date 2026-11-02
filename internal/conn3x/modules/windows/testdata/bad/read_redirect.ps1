# expect: may not write to a file
param($A)
Get-Service > C:\out.txt
