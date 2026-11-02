param($A)
#include safepath

# A task runs whatever sits at its path as its user. So only administrators may
# change that program or any folder on the way, and in its own folder nobody
# else may even add a file: a DLL dropped next to a program loads into it.
function Assert-AdminOnly([string]$p, [switch]$Folder) {
  Assert-FullName $p
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

# Scripts and libraries an interpreter loads: a task naming one runs it.
$script:loadable = '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.sct',
  '.dll', '.ocx', '.cpl', '.py', '.pyw', '.pl', '.rb', '.jar', '.msi', '.msp', '.exe', '.com', '.scr', '.inf', '.csproj', '.proj'

# Assert-Arguments checks every path the arguments name the way the program is
# checked: cmd.exe /c C:\Users\Public\job.bat runs job.bat as the task's user,
# so job.bat must be as safe as cmd.exe. A share is refused, and so is a script
# or library named without a full local path, which would be found somewhere
# Conn3x can't check.
function Assert-Arguments([string]$line) {
  $tokens = foreach ($m in [regex]::Matches($line, '"([^"]*)"|(\S+)')) {
    if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
  }
  # A path can also follow , as in rundll32 x.dll,Entry, or = or @, or > in
  # a redirection.
  foreach ($tok in @($tokens | ForEach-Object { $_ -split '[,=@<>|]' } | Where-Object { $_ })) {
    $m = [regex]::Match($tok, '(?:[A-Za-z]:\\|\\\\|//).*')
    if ($m.Success) {
      $p = $m.Value
      if ($p.StartsWith('\\') -or $p.StartsWith('//')) { throw "the arguments name $p, a share or device path; this task's program would load it from somewhere Conn3x can't check" }
      Assert-FullName $p
      if ([IO.File]::Exists($p)) { Assert-AdminOnly $p }
      elseif ([IO.Directory]::Exists($p)) { Assert-AdminOnly $p -Folder }
      elseif ([IO.Path]::GetExtension($p).ToLowerInvariant() -in $script:loadable) { throw "the arguments name $p, which doesn't exist, so Conn3x can't check who could put it there" }
      continue
    }
    $bare = $tok.Trim("'", ';', '(', ')')
    if ([IO.Path]::GetExtension($bare).ToLowerInvariant() -in $script:loadable) {
      throw "the arguments name $bare without a full local path, so the program could load it from a folder Conn3x can't check. Give its full path."
    }
  }
}

# Whoever can change what a task runs can act as the task's user, whatever its
# run level: the built-in Administrator and service accounts get full rights
# without one. So every task is checked.
Assert-AdminOnly ([string]$A.execute)
if ($A.working_directory) { Assert-AdminOnly ([string]$A.working_directory) -Folder }
if ($A.arguments) { Assert-Arguments ([string]$A.arguments) }

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
