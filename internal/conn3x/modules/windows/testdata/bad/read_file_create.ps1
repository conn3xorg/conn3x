# expect: IO.File::Create isn't on the list
param($A)
[IO.File]::Create($A.a)
