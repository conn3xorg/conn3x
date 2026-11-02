# expect: IO.File::Delete isn't on the list
param($A)
[IO.File]::Delete($A.path)
