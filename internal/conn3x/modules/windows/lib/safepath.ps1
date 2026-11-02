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

function Assert-Folder([string]$p, [switch]$OwnerOnly) {
  $sec = [IO.Directory]::GetAccessControl($p, [Security.AccessControl.AccessControlSections]'Access,Owner')
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
  if ([IO.Path]::GetFullPath($dir) -cne $dir) { throw "$dir is not a full, plain path" }
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
      if ($Create -and $n -eq $parts.Count - 1) { Assert-Folder $at -OwnerOnly } else { Assert-Folder $at }
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

# Set-Rules changes an existing path whose folders are locked.
function Set-Rules([string]$p, [bool]$isDir, $entries, [bool]$exact, $inherit, $owner) {
  $class = if ($isDir) { [IO.Directory] } else { [IO.File] }
  $sec = $class::GetAccessControl($p, [Security.AccessControl.AccessControlSections]::Access)
  if ($exact) {
    foreach ($r in $sec.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) { [void]$sec.RemoveAccessRuleSpecific($r) }
  }
  if ($null -ne $inherit) { $sec.SetAccessRuleProtection((-not $inherit), (-not $exact)) }
  foreach ($e in $entries) { $sec.AddAccessRule((New-Rule $e)) }
  $class::SetAccessControl($p, $sec)
  if ($owner) {
    $o = if ($isDir) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $o.SetOwner((Get-Sid $owner))
    $class::SetAccessControl($p, $o)
  }
}
