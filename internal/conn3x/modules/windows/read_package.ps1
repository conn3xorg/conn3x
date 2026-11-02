param($A)
# The Uninstall keys, in the 64-bit and 32-bit views. Never Win32_Product, which
# can start a repair of every MSI on the host.
foreach ($view in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\') {
  $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($view + $A.code, $false)
  if ($k) {
    $k.Close()
    return @{ installed = $true }
  }
}
@{ installed = $false }
