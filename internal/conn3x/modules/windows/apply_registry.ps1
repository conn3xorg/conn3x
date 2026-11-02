param($A)
$key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($A.key)
try {
  $kind = [Microsoft.Win32.RegistryValueKind]$A.kind
  switch ($A.kind) {
    'Binary' { $value = [Convert]::FromBase64String($A.data) }
    'MultiString' { $value = [string[]]@($A.data) }
    # Registry numbers are signed in .NET; these bits are what's stored.
    'DWord' { $value = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$A.data), 0) }
    'QWord' { $value = [BitConverter]::ToInt64([BitConverter]::GetBytes([uint64]$A.data), 0) }
    default { $value = [string]$A.data }
  }
  $key.SetValue($A.name, $value, $kind)
} finally { $key.Close() }
