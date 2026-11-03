# Included by apply scripts that touch files. Nothing here trusts a path between
# two calls: every folder on the way stays open, without FILE_SHARE_DELETE, so it
# can't be renamed or removed until this process ends, and is opened without
# following links, so a link can't pass for the folder it points at.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class Conn3xFs {
  [StructLayout(LayoutKind.Sequential)]
  public struct Info {
    public uint Attributes;
    public uint C1, C2, A1, A2, W1, W2;
    public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool GetFileInformationByHandle(SafeFileHandle h, out Info info);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool MoveFileExW(string from, string to, uint flags);
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool GetKernelObjectSecurity(SafeFileHandle h, uint info, byte[] sd, uint len, out uint need);
  [DllImport("advapi32.dll")]
  public static extern uint SetSecurityInfo(SafeFileHandle h, int type, uint info, byte[] owner, byte[] group, byte[] dacl, byte[] sacl);
}
'@

$script:held = New-Object Collections.ArrayList
# Who may swap things under a path we write: the machine's own admins and this login.
$script:trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',
  [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
# DELETE, WRITE_DAC, WRITE_OWNER, FILE_DELETE_CHILD and GENERIC_ALL each let an
# account rename or replace what lies below. Adding a new entry doesn't, and what
# a user adds that way is refused below or replaced by our own file.
$script:swapRights = 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40 -bor 0x10000000

function Open-NoFollow([string]$p, [uint32]$access, [uint32]$share) {
  # OPEN_EXISTING. BACKUP_SEMANTICS, which opens folders, and OPEN_REPARSE_POINT,
  # which stops at a link.
  $h = [Conn3xFs]::CreateFileW($p, $access, $share, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
  if ($h.IsInvalid) {
    $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    throw "opening ${p}: $((New-Object ComponentModel.Win32Exception $code).Message)"
  }
  $h
}

function Get-Info($h) {
  $i = New-Object Conn3xFs+Info
  if (-not [Conn3xFs]::GetFileInformationByHandle($h, [ref]$i)) { throw (New-Object ComponentModel.Win32Exception) }
  $i
}

# Hold-Path keeps a path from being renamed or removed until this process ends.
# It needs FILE_READ_DATA: Windows ignores the sharing mode of a handle that only
# reads attributes. Sharing read and write leaves work inside the folder alone.
function Hold-Path([string]$p) {
  $h = Open-NoFollow $p 0x20081 3
  if ($h) { [void]$script:held.Add($h) }
  $h
}

# Stat-Path looks at a path itself, not at what it may point to, and lets go.
function Stat-Path([string]$p) {
  $h = Open-NoFollow $p 0x80 7
  if (-not $h) { return $null }
  try { Get-Info $h } finally { $h.Dispose() }
}

function Assert-NotLink([string]$p, $info) {
  if ($info.Attributes -band 0x400) { throw "$p is a link or junction, which Conn3x won't follow. Use the real path." }
}

# Read-Security reads an object's rules (4), owner (1) or both from a handle. A
# name could mean something else by now: someone who can write in an empty folder
# can turn it into a junction even while it's held, but a handle stays on the folder.
function Read-Security($h, $type, [uint32]$info) {
  $need = [uint32]0
  [void][Conn3xFs]::GetKernelObjectSecurity($h, $info, $null, 0, [ref]$need)
  $bytes = New-Object byte[] $need
  if (-not [Conn3xFs]::GetKernelObjectSecurity($h, $info, $bytes, $need, [ref]$need)) { throw (New-Object ComponentModel.Win32Exception) }
  $sec = New-Object $type
  $sec.SetSecurityDescriptorBinaryForm($bytes)
  $sec
}

# Assert-FullName refuses a name that isn't the path's real one, such as a short name.
function Assert-FullName([string]$p) {
  if ([IO.Path]::GetFullPath($p) -cne $p) { throw "$p is not a full, plain path" }
}

function Assert-Folder([string]$p, $h, [switch]$OwnerOnly) {
  $sec = Read-Security $h ([Security.AccessControl.DirectorySecurity]) 5
  $owner = $sec.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin $script:trusted) { throw "$p belongs to $owner, who could replace what's inside it. Change its owner, or use another path." }
  if ($OwnerOnly) { return }
  foreach ($r in $sec.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -ne 'Allow' -or ($r.PropagationFlags -band 'InheritOnly')) { continue }
    if (([int]$r.FileSystemRights -band $script:swapRights) -and $r.IdentityReference.Value -notin $script:trusted) {
      throw "$($r.IdentityReference.Value) can rename or replace what's inside $p. Remove that right, or use another path."
    }
  }
}

# Lock-Folders holds every folder down to $dir, and refuses a link among them.
# -Strict is for promised access rules, which mean nothing where someone else can
# replace the path afterwards: it also refuses folders others can change. -Create
# makes missing ones and treats the last as the folder being managed: it may start
# with $sec, and who else may write in it is that folder's own configuration.
function Lock-Folders([string]$dir, [switch]$Create, [switch]$Strict, $sec) {
  Assert-FullName $dir
  $root = [IO.Path]::GetPathRoot($dir)
  $at = $root
  $parts = @($root) + @($dir.Substring($root.Length).Split('\', [StringSplitOptions]::RemoveEmptyEntries))
  for ($n = 0; $n -lt $parts.Count; $n++) {
    if ($n) { $at = [IO.Path]::Combine($at, $parts[$n]) }
    $h = Hold-Path $at
    if (-not $h -and $Create) {
      if ($n -eq $parts.Count - 1 -and $sec) { [void][IO.Directory]::CreateDirectory($at, $sec) } else { [void][IO.Directory]::CreateDirectory($at) }
      $h = Hold-Path $at
    }
    if (-not $h) { throw "$at doesn't exist" }
    $i = Get-Info $h
    Assert-NotLink $at $i
    if (-not ($i.Attributes -band 0x10)) { throw "$at is not a folder" }
    if ($Strict) {
      if ($Create -and $n -eq $parts.Count - 1) { Assert-Folder $at $h -OwnerOnly } else { Assert-Folder $at $h }
    }
  }
}

# New-Rule turns one entry into an access rule. Its rights are already a mask.
function New-Rule($e) {
  $sid = Get-Sid $e.principal
  $type = if ($e.allow) { 'Allow' } else { 'Deny' }
  New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights][int]$e.mask,
    [Security.AccessControl.InheritanceFlags][int]$e.flags, [Security.AccessControl.PropagationFlags]::None, $type)
}

function Get-Sid([string]$name) {
  if ($name -match '^S-1-[0-9-]+$') { return [Security.Principal.SecurityIdentifier]$name }
  ([Security.Principal.NTAccount]$name).Translate([Security.Principal.SecurityIdentifier])
}

# New-Security builds a descriptor holding exactly these entries and nothing
# inherited, for a new file or folder to start with.
function New-Security($type, $entries) {
  $sec = New-Object $type
  $sec.SetAccessRuleProtection($true, $false)
  foreach ($e in $entries) { $sec.AddAccessRule((New-Rule $e)) }
  $sec
}

# Set-Rules changes an existing path whose folders are locked, through a handle
# opened without following links, so the rules land on this object and no other.
function Set-Rules([string]$p, [bool]$isDir, $entries, [bool]$exact, $inherit, $owner) {
  # WRITE_DAC, and WRITE_OWNER when it's needed, on top of what a hold has.
  $access = 0x20081 -bor 0x40000
  if ($owner) { $access = $access -bor 0x80000 }
  $h = Open-NoFollow $p $access 3
  if (-not $h) { throw "$p doesn't exist" }
  [void]$script:held.Add($h)
  Assert-NotLink $p (Get-Info $h)
  $type = if ($isDir) { [Security.AccessControl.DirectorySecurity] } else { [Security.AccessControl.FileSecurity] }
  $sec = Read-Security $h $type 4
  if ($exact) {
    foreach ($r in $sec.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) { [void]$sec.RemoveAccessRuleSpecific($r) }
  }
  if ($null -ne $inherit) { $sec.SetAccessRuleProtection((-not $inherit), (-not $exact)) }
  foreach ($e in $entries) { $sec.AddAccessRule((New-Rule $e)) }
  $raw = New-Object Security.AccessControl.RawSecurityDescriptor($sec.GetSecurityDescriptorBinaryForm(), 0)
  $dacl = New-Object byte[] $raw.DiscretionaryAcl.BinaryLength
  $raw.DiscretionaryAcl.GetBinaryForm($dacl, 0)
  # DACL, plus PROTECTED_DACL or UNPROTECTED_DACL. 1 is SE_FILE_OBJECT.
  $info = if ($sec.AreAccessRulesProtected) { [uint32]2147483652 } else { [uint32]536870916 }
  $code = [Conn3xFs]::SetSecurityInfo($h, 1, $info, $null, $null, $dacl, $null)
  if ($code) { throw (New-Object ComponentModel.Win32Exception ([int]$code)) }
  if ($owner) {
    $sid = Get-Sid $owner
    $bytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($bytes, 0)
    $code = [Conn3xFs]::SetSecurityInfo($h, 1, 1, $bytes, $null, $null, $null)
    if ($code) { throw (New-Object ComponentModel.Win32Exception ([int]$code)) }
  }
}

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

# A task, or a site's app pool, runs whatever sits at its path as its user. So only administrators may
# change that program or any folder on the way, and in its own folder nobody
# else may even add a file: a DLL dropped next to a program loads into it.
function Assert-AdminOnly([string]$p, [switch]$Folder, [switch]$Inherited, [string]$Runner = 'this task') {
  Assert-PlainPath $p
  $dir = if ($Folder) { $p.TrimEnd('\') } else { [IO.Path]::GetDirectoryName($p) }
  Lock-Folders $dir -Strict
  # FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY and GENERIC_WRITE, as well as swapping.
  $write = $script:swapRights -bor 0x2 -bor 0x4 -bor 0x40000000
  $sec = Read-Security (Hold-Path $dir) ([Security.AccessControl.DirectorySecurity]) 4
  foreach ($r in $sec.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    # -Inherited: a site's files and subfolders inherit what the folder hands
    # down, so a rule that skips the folder itself still lets others write them.
    $applies = -not ($r.PropagationFlags -band 'InheritOnly') -or ($Inherited -and [int]$r.InheritanceFlags)
    if ($r.AccessControlType -eq 'Allow' -and $applies -and ([int]$r.FileSystemRights -band $write) -and $r.IdentityReference.Value -notin $script:trusted) {
      throw "$($r.IdentityReference.Value) can add or replace files in $dir, and $Runner would run what's there as its user. Use a folder only administrators can change."
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
    if ($owner -notin $script:trusted) { throw "$p belongs to $owner, who could change it, and $Runner would run it as its user" }
    foreach ($r in $fs.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      # FILE_WRITE_DATA and FILE_APPEND_DATA, on top of the rights above.
      if ($r.AccessControlType -eq 'Allow' -and ([int]$r.FileSystemRights -band $write) -and $r.IdentityReference.Value -notin $script:trusted) {
        throw "$($r.IdentityReference.Value) can change $p, and $Runner would run it as its user"
      }
    }
  } finally { $h.Dispose() }
}
