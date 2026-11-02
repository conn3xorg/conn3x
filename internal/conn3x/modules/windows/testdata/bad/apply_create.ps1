# expect: Create makes code from a string
param($A)
& ([scriptblock]::Create($A.code))
