# expect: set a property of something
param($A)
[Environment]::CurrentDirectory = $A.a
