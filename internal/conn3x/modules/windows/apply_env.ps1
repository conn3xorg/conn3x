param($A)
$root = if ($A.user) { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
$key = $root.CreateSubKey($A.key)
try {
  if ($A.absent) { $key.DeleteValue($A.name, $false); return }
  # Keep a String or ExpandString as it is: Path is ExpandString, so its
  # %SystemRoot% stays unexpanded. A new value with % in it is ExpandString.
  $string = [Microsoft.Win32.RegistryValueKind]::String
  $expand = [Microsoft.Win32.RegistryValueKind]::ExpandString
  $kind = if ($A.value.Contains('%')) { $expand } else { $string }
  if ($null -ne $key.GetValue($A.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) {
    $old = $key.GetValueKind($A.name)
    if ($old -eq $string -or $old -eq $expand) { $kind = $old }
  }
  $key.SetValue($A.name, [string]$A.value, $kind)
} finally { $key.Close() }
