param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include safepath
#include download

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
  $admins = @(
    @{ principal = 'S-1-5-18'; mask = 0x1F01FF; flags = 3; allow = $true },
    @{ principal = 'S-1-5-32-544'; mask = 0x1F01FF; flags = 3; allow = $true })
  $own = New-Security ([Security.AccessControl.DirectorySecurity]) $admins
  $dir = Join-Path $env:ProgramData 'Conn3x'
  $stage = Join-Path $dir 'packages'
  # A folder that was already there has whatever rules it was made with, such
  # as ProgramData's, which let any user add to it. So each gets these rules
  # again, through its held handle. Reapplying them to a new one changes nothing.
  foreach ($d in $dir, $stage) {
    Lock-Folders $d -Create -Strict $own
    Assert-Folder $d $script:folder
    Set-Rules $script:folder $true $admins $true $false $null
  }
  $leaf = [guid]::NewGuid().ToString('N') + '.msi'
  $file = Join-Path $stage $leaf
  # Made in the held folder, not by its name, with the same access as a temp
  # file in apply_file.ps1 but shared for reading.
  $made = [Conn3xFs]::OpenIn($script:folder, $leaf, 0x17019F, 0, 2, 0x40, $null)
  $out = New-Object IO.FileStream($made, [IO.FileAccess]::ReadWrite)
  try {
    try {
      # Someone who opened the folder while they could still write to it could
      # have made it a junction while it was empty. With our file in it, not any more.
      Assert-NotLink $stage (Get-Info $script:folder)
      # What a run that died left behind. A file another run still holds can't
      # be deleted, and stays. Only now: with a file of ours in it the folder
      # can't be turned into a junction, so its name still means this folder.
      foreach ($f in [IO.Directory]::GetFiles($stage)) { if ($f -ne $file) { try { [IO.File]::Delete($f) } catch { } } }
      if ($A.url) {
        Save-Download ([string]$A.url) $out ([long]$A.max_bytes) ([bool]$A.allow_http)
      } else {
        $in = [IO.File]::Open([string]$A.source, 'Open', 'Read', 'Read')
        try { $in.CopyTo($out) } finally { $in.Dispose() }
      }
      $out.Flush($true)
    } finally { $out.Dispose() }
    # From here until msiexec is done, this handle lets others read the file
    # but not change, rename or delete it: what was hashed is what installs.
    # FILE_GENERIC_READ, shared for reading.
    $held = New-Object IO.FileStream((Open-In $leaf 0x120089 1), [IO.FileAccess]::Read)
    try {
      $sum = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($held))).Replace('-', '').ToLowerInvariant()
      if ($sum -ne $A.sha256) { throw "the package's SHA-256 is $sum, not $($A.sha256) as configured; nothing was installed" }
      $code = Invoke-Msiexec ('/i "' + $file + '" /qn /norestart ' + $A.properties)
    } finally { $held.Dispose() }
  } finally {
    # DELETE, through the held folder.
    $gone = Open-In $leaf 0x10080 7
    if ($gone) { try { [Conn3xFs]::Remove($gone) } finally { $gone.Dispose() } }
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
