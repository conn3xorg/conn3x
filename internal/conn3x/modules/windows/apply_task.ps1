param($A)
#include safepath

# Assert-PlainPath refuses what GetFullPath lets through unchanged, as seen on
# Server 2025: a short name such as PROGRA~1, and a name that starts or ends
# in a space or ends in a dot. And it needs a fixed NTFS drive: a FAT stick or
# a network drive has no access rules to check, or someone else's.
function Assert-PlainPath([string]$p) {
  Assert-FullName $p
  foreach ($seg in $p.Substring(3).Split('\')) {
    if ($seg -and ($seg.EndsWith(' ') -or $seg.EndsWith('.') -or $seg.StartsWith(' ') -or $seg -match '^[^.]{1,7}~[0-9]+(\.[^.]{1,3})?$')) {
      throw "$p has a short name, or a name that starts or ends in a space or ends in a dot; write the full, plain path"
    }
  }
  $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($p))
  if ($drive.DriveType -ne 'Fixed' -or $drive.DriveFormat -ne 'NTFS') { throw "$p isn't on a fixed NTFS drive, so Conn3x can't check who can change it" }
}

# A task runs whatever sits at its path as its user. So only administrators may
# change that program or any folder on the way, and in its own folder nobody
# else may even add a file: a DLL dropped next to a program loads into it.
function Assert-AdminOnly([string]$p, [switch]$Folder) {
  Assert-PlainPath $p
  $dir = if ($Folder) { $p.TrimEnd('\') } else { [IO.Path]::GetDirectoryName($p) }
  Lock-Folders $dir -Strict
  # FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY and GENERIC_WRITE, as well as swapping.
  $write = $script:swapRights -bor 0x2 -bor 0x4 -bor 0x40000000
  $sec = Read-Security (Hold-Path $dir) ([Security.AccessControl.DirectorySecurity]) 4
  foreach ($r in $sec.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -eq 'Allow' -and -not ($r.PropagationFlags -band 'InheritOnly') -and ([int]$r.FileSystemRights -band $write) -and $r.IdentityReference.Value -notin $script:trusted) {
      throw "$($r.IdentityReference.Value) can add or replace files in $dir, and this task would run what's there as its user. Use a folder only administrators can change."
    }
  }
  if ($Folder) { return }
  # READ_CONTROL and FILE_READ_ATTRIBUTES, without following a link.
  $h = Open-NoFollow $p 0x20080 7
  if (-not $h) { throw "$p doesn't exist, so Conn3x can't check who can change it" }
  try {
    Assert-NotLink $p (Get-Info $h)
    $fs = Read-Security $h ([Security.AccessControl.FileSecurity]) 5
    $owner = $fs.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $script:trusted) { throw "$p belongs to $owner, who could change it, and this task would run it as its user" }
    foreach ($r in $fs.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      # FILE_WRITE_DATA and FILE_APPEND_DATA, on top of the rights above.
      if ($r.AccessControlType -eq 'Allow' -and ([int]$r.FileSystemRights -band $write) -and $r.IdentityReference.Value -notin $script:trusted) {
        throw "$($r.IdentityReference.Value) can change $p, and this task would run it as its user"
      }
    }
  } finally { $h.Dispose() }
}

# Assert-Path checks a path the arguments name. One that doesn't exist yet is
# judged by the deepest folder on its way that does: whoever can add files
# there can put something at that path later.
function Assert-Path([string]$p) {
  Assert-PlainPath $p
  if ([IO.Path]::GetPathRoot($p) -eq $p) { throw "the arguments name the drive $p itself" }
  if ([IO.File]::Exists($p)) { Assert-AdminOnly $p; return }
  if ([IO.Directory]::Exists($p)) { Assert-AdminOnly $p -Folder; return }
  $parent = [IO.Path]::GetDirectoryName($p)
  while ($parent -and -not [IO.Directory]::Exists($parent)) { $parent = [IO.Path]::GetDirectoryName($parent) }
  if (-not $parent -or [IO.Path]::GetPathRoot($parent) -eq $parent) {
    throw "the arguments name $p, which doesn't exist, and anyone can make folders at the top of the drive; make its folder first, admin-only"
  }
  Assert-AdminOnly $parent -Folder
}

# Whoever can change what a task runs can act as the task's user, whatever its
# run level: the built-in Administrator and service accounts get full rights
# without one. So every task is checked.
Assert-AdminOnly ([string]$A.execute)
# A renamed copy of an interpreter still knows its own name.
if (-not $A.allow_interpreter) {
  $own = ([string](Get-Item -LiteralPath ([string]$A.execute)).VersionInfo.OriginalFilename).ToLowerInvariant()
  # System32's own programs give it with .MUI on the end, as in Cmd.Exe.MUI.
  $own = $own -replace '\.mui$', ''
  # Compare names without the extension: .NET hosts such as pwsh give
  # pwsh.dll. An empty name was already checked by its file name in Go.
  $stem = [IO.Path]::GetFileNameWithoutExtension($own)
  $stems = @($A.interpreters) | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension([string]$_) }
  if ($stem -and ($stem -in $stems -or $stem.StartsWith('python'))) {
    throw "$($A.execute) is $own, which runs code from its arguments: set allow_interpreter = true if every script it runs is admin-only"
  }
}
if ($A.working_directory) { Assert-AdminOnly ([string]$A.working_directory) -Folder }
# Every full path in the arguments, as Go found them; Go refused anything it
# couldn't read as one.
foreach ($p in @($A.check_paths)) { if ($p) { Assert-Path ([string]$p) } }
# data_paths: only read or written as data, so anyone may change them, but
# they must still be plain paths on a fixed NTFS drive.
foreach ($p in @($A.data_paths)) { if ($p) { Assert-PlainPath ([string]$p) } }

# The logon follows from the account as Windows resolves it, not its spelling.
$sid = (Get-Sid ([string]$A.user)).Value
$service = $sid -in 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
if ($service -and $A.has_password) { throw "$($A.user) is a service account, which has no password: remove password_wo" }
# TASK_LOGON_PASSWORD, TASK_LOGON_S4U, TASK_LOGON_SERVICE_ACCOUNT.
$logon = if ($A.has_password) { 1 } elseif ($service) { 5 } else { 2 }

$svc = New-Object -ComObject Schedule.Service
$svc.Connect()
$folder = $svc.GetFolder('\')
foreach ($part in ([string]$A.path).Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
  try { $folder = $folder.GetFolder($part) } catch { $folder = $folder.CreateFolder($part, $null) }
}
$def = $svc.NewTask(0)
if ($null -ne $A.description) { $def.RegistrationInfo.Description = [string]$A.description }
$def.Settings.Enabled = [bool]$A.enabled
$def.Principal.RunLevel = $(if ($A.highest) { 1 } else { 0 })
$def.Principal.LogonType = $logon
$def.Principal.UserId = [string]$A.user
$act = $def.Actions.Create(0)
$act.Path = [string]$A.execute
if ($A.arguments) { $act.Arguments = [string]$A.arguments }
if ($A.working_directory) { $act.WorkingDirectory = [string]$A.working_directory }
foreach ($tr in @($A.triggers)) {
  if (-not $tr) { continue }
  $t = $def.Triggers.Create(@{ once = 1; daily = 2; boot = 8; logon = 9 }[[string]$tr['type']])
  if ($tr['at']) { $t.StartBoundary = [string]$tr['at'] }
  if ($tr['type'] -eq 'daily') { $t.DaysInterval = [int16]$tr['days'] }
}
# The password reaches Task Scheduler only through this COM call: a cmdlet's
# parameters can be recorded by a logging policy, a method's arguments can't.
$pw = $null
if ($A.has_password) { $pw = [string]$A.password }
[void]$folder.RegisterTaskDefinition([string]$A.name, $def, 6, [string]$A.user, $pw, $logon)
