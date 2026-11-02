param($A)
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($A.key, $true)
if (-not $key) { return }
try { $key.DeleteValue($A.name, $false) } finally { $key.Close() }
