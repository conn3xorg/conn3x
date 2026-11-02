param($A)
#include safepath

# The one way this module runs a native program. Every value on the line is
# Conn3x's own or was checked in Go: a GUID, a path below, or quoted properties.
function Invoke-Msiexec([string]$line) {
  $psi = New-Object Diagnostics.ProcessStartInfo((Join-Path $env:WINDIR 'System32\msiexec.exe'), $line)
  $psi.UseShellExecute = $false
  $p = [Diagnostics.Process]::Start($psi)
  $p.WaitForExit()
  $p.ExitCode
}

if (-not $A.present) {
  $code = Invoke-Msiexec ('/x ' + $A.product_code + ' /qn /norestart')
} else {
  # Packages wait in a folder only SYSTEM and Administrators can write to, and
  # whose folders on the way nobody else can rename or replace.
  $own = New-Security ([Security.AccessControl.DirectorySecurity]) @(
    @{ principal = 'S-1-5-18'; mask = 0x1F01FF; flags = 3; allow = $true },
    @{ principal = 'S-1-5-32-544'; mask = 0x1F01FF; flags = 3; allow = $true })
  $dir = Join-Path $env:ProgramData 'Conn3x'
  Lock-Folders $dir -Create -Strict $own
  $stage = Join-Path $dir 'packages'
  Lock-Folders $stage -Create -Strict $own
  Assert-Folder $stage (Hold-Path $stage)
  $file = Join-Path $stage ([guid]::NewGuid().ToString('N') + '.msi')
  try {
    if ($A.url) {
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      (New-Object Net.WebClient).DownloadFile([string]$A.url, $file)
    } else {
      $in = [IO.File]::Open([string]$A.source, 'Open', 'Read', 'Read')
      try {
        $out = [IO.File]::Open($file, 'CreateNew', 'Write', 'None')
        try { $in.CopyTo($out) } finally { $out.Dispose() }
      } finally { $in.Dispose() }
    }
    # From here until msiexec is done, this handle lets others read the file
    # but not change, rename or delete it: what was hashed is what installs.
    $held = [IO.File]::Open($file, 'Open', 'Read', 'Read')
    try {
      $sum = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($held))).Replace('-', '').ToLowerInvariant()
      if ($sum -ne $A.sha256) { throw "the package's SHA-256 is $sum, not $($A.sha256) as configured; nothing was installed" }
      $code = Invoke-Msiexec ('/i "' + $file + '" /qn /norestart ' + $A.properties)
    } finally { $held.Dispose() }
  } finally {
    if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) }
  }
}

$restart = $false
switch ($code) {
  0 {}
  3010 { $restart = $true }
  1641 { $restart = $true }
  1618 { throw 'another installation is running (msiexec 1618); try again when it ends' }
  default { throw "msiexec exited with $code" }
}
if ($restart) {
  # Volatile: the key goes with the next boot. windows_reboot's check finds it,
  # so a run that stops before its reboot step plans that reboot next time.
  $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Conn3x\RebootRequired', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Microsoft.Win32.RegistryOptions]::Volatile)
  $k.Close()
}
@{ restart = $restart }
