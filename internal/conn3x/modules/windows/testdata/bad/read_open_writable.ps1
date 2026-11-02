# expect: must say $false for writable
param($A)
[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($A.key, $true)
