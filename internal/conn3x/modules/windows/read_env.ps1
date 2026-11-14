param($A)
$root = if ($A.user) { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
$key = $root.OpenSubKey($A.key, $false)
if (-not $key) { return @{ exists = $false } }
try {
  $value = $key.GetValue($A.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if ($null -eq $value) { return @{ exists = $false } }
  @{ exists = $true; kind = [string]$key.GetValueKind($A.name); value = [string]$value }
} finally { $key.Close() }
