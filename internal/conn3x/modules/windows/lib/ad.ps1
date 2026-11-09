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
# run that stops before its reboot step plans that reboot next time. $domain,
# if given, names the domain the host was promoted into, which Windows itself
# shows only after the reboot.
function Set-RebootMarker($domain) {
  $parent = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\Conn3x')
  try {
    $k = $parent.CreateSubKey('RebootRequired', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Microsoft.Win32.RegistryOptions]::Volatile)
    try { if ($domain) { $k.SetValue('PromotedDomain', [string]$domain) } } finally { $k.Close() }
  } finally { $parent.Close() }
}

# For the OU, group and user scripts: the ActiveDirectory module, without the
# AD: drive, which would only slow the import down.
function Import-AD {
  $env:ADPS_LoadDefaultDrive = 0
  Import-Module ActiveDirectory -ErrorAction Stop
  # These scripts run on a DC. Without -Server, the DC locator can pick
  # another one that hasn't replicated a change yet, so a read straight
  # after a write could miss it. A script that names a server, such as the
  # global catalog check, still gets the one it names.
  $global:PSDefaultParameterValues['*-AD*:Server'] = 'localhost'
}

# Sets one text attribute, or clears it for "", which the cmdlets refuse as a
# value. $null leaves it as it is.
function Set-ADText($dn, $attr, $value) {
  if ($null -eq $value) { return }
  if ([string]$value -eq '') { Set-ADObject -Identity $dn -Clear $attr } else { Set-ADObject -Identity $dn -Replace @{ $attr = [string]$value } }
}

# The SIDs the login has, itself and through its groups.
function Get-LoginSIDs {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  @($id.User.Value) + @($id.Groups | ForEach-Object { $_.Value })
}
