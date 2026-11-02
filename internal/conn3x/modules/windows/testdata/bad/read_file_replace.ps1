# expect: IO.File::Replace isn't on the list
param($A)
[IO.File]::Replace($A.a, $A.b, $null)
