param($A)
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($A.key, $false)
if (-not $key) { return @{ exists = $false } }
try {
  $value = $key.GetValue($A.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if ($null -eq $value) { return @{ exists = $false } }
  $kind = [string]$key.GetValueKind($A.name)
  if ($A.hash_only) {
    # A secret's data must not leave here: output goes through a cmdlet, which a
    # logging policy can record. This hashes the same text Go hashes.
    $text = switch ($kind) {
      'Binary' { ([BitConverter]::ToString([byte[]]$value)).Replace('-', '').ToLowerInvariant() }
      'MultiString' { [string]::Join("`n", [string[]]$value) }
      'DWord' { [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$value), 0).ToString() }
      'QWord' { [BitConverter]::ToUInt64([BitConverter]::GetBytes([long]$value), 0).ToString() }
      default { [string]$value }
    }
    $sum = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
    return @{ exists = $true; kind = $kind; sha256 = ([BitConverter]::ToString($sum)).Replace('-', '').ToLowerInvariant() }
  }
  $data = switch ($kind) {
    'Binary' { [Convert]::ToBase64String([byte[]]$value) }
    'MultiString' { ,[string[]]$value }
    default { [string]$value }
  }
  @{ exists = $true; kind = $kind; data = $data }
} finally { $key.Close() }
