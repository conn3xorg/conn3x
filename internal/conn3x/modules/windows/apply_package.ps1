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

# Save-Download downloads into $file, following up to five redirects itself so
# none can drop from https to http unless that's allowed, and stops at $max
# bytes. A partial file is left for the caller to delete.
function Save-Download([string]$url, [string]$file, [long]$max, [bool]$allowHttp) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $uri = New-Object Uri($url)
  for ($hop = 0; $hop -le 5; $hop++) {
    if ($uri.Scheme -ne 'https' -and -not ($allowHttp -and $uri.Scheme -eq 'http')) {
      throw "the download went to a $($uri.Scheme) address, $($uri.Host); only https is allowed, or http with allow_http"
    }
    # A connection dropped before any answer is tried again, twice; an answer,
    # even an error, is final.
    $res = $null
    for ($try = 1; -not $res; $try++) {
      $req = [Net.WebRequest]::Create($uri)
      $req.AllowAutoRedirect = $false
      $req.KeepAlive = $false
      try { $res = $req.GetResponse() } catch {
        # PowerShell wraps a method's exception, so look inside for the
        # WebException: its response carries the HTTP status.
        $we = $_.Exception
        while ($we -and $we -isnot [Net.WebException]) { $we = $we.InnerException }
        if ($we -and $we.Response) { $res = $we.Response }
        elseif ($try -ge 3) { throw }
        else { Start-Sleep -Seconds 2 }
      }
    }
    $code = [int]$res.StatusCode
    if ($code -ge 300 -and $code -lt 400) {
      $next = $res.Headers['Location']
      $res.Close()
      if (-not $next) { throw "the download redirected (HTTP $code) without saying where" }
      $uri = New-Object Uri($uri, $next)
      continue
    }
    if ($code -ne 200) { $res.Close(); throw "the download failed with HTTP $code" }
    if ($res.ContentLength -gt $max) { $res.Close(); throw "the download is $($res.ContentLength) bytes, more than max_size_mb allows" }
    $in = $res.GetResponseStream()
    $out = [IO.File]::Open($file, 'CreateNew', 'Write', 'None')
    try {
      $buf = New-Object byte[] 65536
      $total = [long]0
      while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) {
        $total += $n
        if ($total -gt $max) { throw "the download is more than max_size_mb allows" }
        $out.Write($buf, 0, $n)
      }
    } finally { $out.Dispose(); $in.Dispose(); $res.Close() }
    return
  }
  throw 'the download redirected more than five times'
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
  # What a run that died left behind. A file another run still holds can't be
  # deleted, and stays.
  foreach ($f in [IO.Directory]::GetFiles($stage)) { try { [IO.File]::Delete($f) } catch { } }
  $file = Join-Path $stage ([guid]::NewGuid().ToString('N') + '.msi')
  try {
    if ($A.url) {
      Save-Download ([string]$A.url) $file ([long]$A.max_bytes) ([bool]$A.allow_http)
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
  # The parent first, as an ordinary key: made in the same call, it would be
  # volatile too, and take anything else Conn3x keeps there with it.
  $parent = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Conn3x')
  try {
    $k = $parent.CreateSubKey('RebootRequired', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Microsoft.Win32.RegistryOptions]::Volatile)
    $k.Close()
  } finally { $parent.Close() }
}
@{ restart = $restart }
