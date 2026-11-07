# For the scripts that promote a domain controller or join a domain. The
# folder checks need safepath, included before this.

# Folders for the database, logs and SYSVOL. On a new volume anyone may make a
# folder at the top and own it, or a junction to one, and AD keeps its secrets
# and every DC's logon scripts in these. So each must be admin-only, owned by a
# trusted account and no link, or missing. Returns the missing ones, for
# New-ADFolders once AD DS is known to be there. The holds Lock-Folders takes
# keep them all in place while promotion runs.
function Test-ADFolders($paths) {
  $missing = @()
  foreach ($p in @(@($paths) | Where-Object { $_ } | Select-Object -Unique)) {
    Assert-PlainPath $p
    Lock-Folders ([IO.Path]::GetDirectoryName($p)) -Strict
    if (Stat-Path $p) {
      Assert-AdminOnly $p -Folder -Inherited -Runner 'Active Directory'
      # Held and admin-only now, so nothing new can appear; what's already
      # inside could belong to anyone, with rules of its own.
      if ([IO.Directory]::EnumerateFileSystemEntries($p).GetEnumerator().MoveNext()) { throw "$p isn't empty. Give Active Directory an empty folder, or one that doesn't exist yet." }
    } else { $missing += $p }
  }
  , $missing
}

# Makes each folder with SYSTEM and Administrators only, and holds it.
function New-ADFolders($missing) {
  $admins = @(@{ principal = 'S-1-5-18'; mask = 0x1F01FF; flags = 3; allow = $true }, @{ principal = 'S-1-5-32-544'; mask = 0x1F01FF; flags = 3; allow = $true })
  foreach ($p in $missing) { Lock-Folders $p -Create -Strict (New-Security ([Security.AccessControl.DirectorySecurity]) $admins) }
}

# As apply_package.ps1: a volatile key that windows_reboot's check finds, so a
# run that stops before its reboot step plans that reboot next time.
function Set-RebootMarker {
  $parent = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Conn3x')
  try {
    $k = $parent.CreateSubKey('RebootRequired', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Microsoft.Win32.RegistryOptions]::Volatile)
    $k.Close()
  } finally { $parent.Close() }
}
