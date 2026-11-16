# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0

# Included by apply scripts that touch files. Nothing here trusts a path between
# two calls: every folder on the way stays open, without FILE_SHARE_DELETE, so it
# can't be renamed or removed until this process ends, and is opened without
# following links, so a link can't pass for the folder it points at. Each folder
# is opened from the handle on the one above it, and so is what a script reads,
# writes, renames or deletes inside the last: a name is only ever looked up in a
# folder that's held, never walked to again from the drive.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
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
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool SetFileInformationByHandle(SafeFileHandle h, int cls, IntPtr info, uint size);
  [StructLayout(LayoutKind.Sequential)]
  struct UnicodeString { public ushort Length, Max; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)]
  struct ObjectAttributes { public int Length; public IntPtr Root, Name; public uint Attributes; public IntPtr Security, Qos; }
  [StructLayout(LayoutKind.Sequential)]
  struct IoStatus { public IntPtr Status, Information; }
  [DllImport("ntdll.dll")]
  static extern int NtCreateFile(out SafeFileHandle h, uint access, ref ObjectAttributes oa, out IoStatus io, IntPtr size, uint attrs, uint share, uint disposition, uint options, IntPtr ea, uint eaLen);
  [DllImport("ntdll.dll")]
  static extern int NtSetInformationFile(SafeFileHandle h, out IoStatus io, IntPtr info, uint size, int cls);
  [DllImport("ntdll.dll")]
  static extern int RtlNtStatusToDosError(int status);

  // OpenIn opens the entry called leaf in a folder that's already open, or
  // makes it. Windows starts at the handle, not at a path, so the entry is in
  // that folder whatever its name leads to by now. A link is opened, not
  // followed. An empty leaf opens the folder's own object again. It returns
  // null for a missing entry.
  public static SafeFileHandle OpenIn(SafeFileHandle dir, string leaf, uint access, uint share, uint disposition, uint options, byte[] security) {
    if (leaf.IndexOfAny(new[] { '\\', '/', ':' }) >= 0 || leaf == "." || leaf == "..") throw new ArgumentException(leaf + " is not one plain name");
    IntPtr name = Marshal.StringToHGlobalUni(leaf), us = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString))), sd = IntPtr.Zero;
    bool held = false;
    try {
      Marshal.StructureToPtr(new UnicodeString { Length = (ushort)(leaf.Length * 2), Max = (ushort)(leaf.Length * 2), Buffer = name }, us, false);
      if (security != null) { sd = Marshal.AllocHGlobal(security.Length); Marshal.Copy(security, 0, sd, security.Length); }
      dir.DangerousAddRef(ref held);
      // OBJ_CASE_INSENSITIVE, as any Windows path is.
      var oa = new ObjectAttributes { Length = Marshal.SizeOf(typeof(ObjectAttributes)), Root = dir.DangerousGetHandle(), Name = us, Attributes = 0x40, Security = sd };
      SafeFileHandle h; IoStatus io;
      // SYNCHRONIZE with FILE_SYNCHRONOUS_IO_NONALERT, for plain blocking reads
      // and writes; FILE_OPEN_FOR_BACKUP_INTENT, which opens folders; and
      // FILE_OPEN_REPARSE_POINT, which stops at a link.
      int status = NtCreateFile(out h, access | 0x100000, ref oa, out io, IntPtr.Zero, 0x80, share, disposition, options | 0x204020, IntPtr.Zero, 0);
      // STATUS_OBJECT_NAME_NOT_FOUND
      if (status == unchecked((int)0xC0000034)) return null;
      if (status != 0) throw new Win32Exception(RtlNtStatusToDosError(status));
      return h;
    } finally {
      if (held) dir.DangerousRelease();
      Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(us);
      if (sd != IntPtr.Zero) Marshal.FreeHGlobal(sd);
    }
  }

  // RenameTo gives an open file a new name in the folder it's in, replacing a
  // file already called that. No path is involved: the file is the handle's.
  // Straight to the kernel, because kernel32's SetFileInformationByHandle takes
  // a bare name as one in the process's current folder and moves the file there.
  public static void RenameTo(SafeFileHandle h, string leaf) {
    if (leaf.IndexOfAny(new[] { '\\', '/', ':' }) >= 0 || leaf == "." || leaf == "..") throw new ArgumentException(leaf + " is not one plain name");
    // FILE_RENAME_INFORMATION: ReplaceIfExists, a null RootDirectory, the name's length in bytes, the name.
    int at = IntPtr.Size * 2, size = at + 4 + leaf.Length * 2 + 2;
    IntPtr buf = Marshal.AllocHGlobal(size);
    try {
      for (int n = 0; n < size; n++) Marshal.WriteByte(buf, n, 0);
      Marshal.WriteByte(buf, 0, 1);
      Marshal.WriteInt32(buf, at, leaf.Length * 2);
      Marshal.Copy(leaf.ToCharArray(), 0, IntPtr.Add(buf, at + 4), leaf.Length);
      IoStatus io;
      // 10 is FileRenameInformation.
      int status = NtSetInformationFile(h, out io, buf, (uint)size, 10);
      if (status != 0) throw new Win32Exception(RtlNtStatusToDosError(status));
    } finally { Marshal.FreeHGlobal(buf); }
  }

  // Remove deletes what the handle is on, once the handle closes.
  public static void Remove(SafeFileHandle h) {
    IntPtr buf = Marshal.AllocHGlobal(1);
    try {
      Marshal.WriteByte(buf, 0, 1);
      // 4 is FileDispositionInfo.
      if (!SetFileInformationByHandle(h, 4, buf, 1)) throw new Win32Exception();
    } finally { Marshal.FreeHGlobal(buf); }
  }
  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern bool GetKernelObjectSecurity(SafeFileHandle h, uint info, byte[] sd, uint len, out uint need);
  [DllImport("advapi32.dll")]
  public static extern uint SetSecurityInfo(SafeFileHandle h, int type, uint info, byte[] owner, byte[] group, byte[] dacl, byte[] sacl);
}
'@

$script:held = New-Object Collections.ArrayList
$script:folder = $null # the folder Lock-Folders last went down to
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

# Open-In opens what's called $leaf in the folder Lock-Folders went down to,
# itself and not what it may point to, or returns nothing when it isn't there.
function Open-In([string]$leaf, [uint32]$access, [uint32]$share) {
  [Conn3xFs]::OpenIn($script:folder, $leaf, $access, $share, 1, 0, $null) # FILE_OPEN
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
  $h = $null
  for ($n = 0; $n -lt $parts.Count; $n++) {
    # A hold needs FILE_READ_DATA: Windows ignores the sharing mode of a handle
    # that only reads attributes. Sharing read and write leaves work inside the
    # folder alone. The drive is the one name looked up from the top.
    if (-not $n) { $h = Open-NoFollow $at 0x20081 3 }
    else {
      $at = [IO.Path]::Combine($at, $parts[$n])
      $sd = $null
      if ($Create -and $sec -and $n -eq $parts.Count - 1) { $sd = $sec.GetSecurityDescriptorBinaryForm() }
      # FILE_OPEN_IF with FILE_DIRECTORY_FILE makes a missing folder; FILE_OPEN doesn't.
      $h = [Conn3xFs]::OpenIn($h, $parts[$n], 0x20081, 3, $(if ($Create) { 3 } else { 1 }), $(if ($Create) { 1 } else { 0 }), $sd)
    }
    if (-not $h) { throw "$at doesn't exist" }
    [void]$script:held.Add($h)
    $i = Get-Info $h
    Assert-NotLink $at $i
    if (-not ($i.Attributes -band 0x10)) { throw "$at is not a folder" }
    if ($Strict) {
      if ($Create -and $n -eq $parts.Count - 1) { Assert-Folder $at $h -OwnerOnly } else { Assert-Folder $at $h }
    }
  }
  $script:folder = $h
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

# Set-Rules changes the file or folder a held handle is on. It opens that same
# object again for the rights it needs, so the rules land on it and no other.
function Set-Rules($held, [bool]$isDir, $entries, [bool]$exact, $inherit, $owner) {
  # WRITE_DAC, and WRITE_OWNER when it's needed, on top of what a hold has.
  $access = 0x20081 -bor 0x40000
  if ($owner) { $access = $access -bor 0x80000 }
  $h = [Conn3xFs]::OpenIn($held, '', $access, 3, 1, 0, $null)
  [void]$script:held.Add($h)
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
function Assert-AdminOnly([string]$p, [switch]$Folder, [switch]$Inherited, [switch]$Contents, [string]$Runner = 'this task') {
  Assert-PlainPath $p
  $dir = if ($Folder) { $p.TrimEnd('\') } else { [IO.Path]::GetDirectoryName($p) }
  Lock-Folders $dir -Strict
  # FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY and GENERIC_WRITE, as well as swapping.
  $write = $script:swapRights -bor 0x2 -bor 0x4 -bor 0x40000000
  $sec = Read-Security $script:folder ([Security.AccessControl.DirectorySecurity]) 4
  foreach ($r in $sec.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    # -Inherited: a site's files and subfolders inherit what the folder hands
    # down, so a rule that skips the folder itself still lets others write them.
    $applies = -not ($r.PropagationFlags -band 'InheritOnly') -or ($Inherited -and [int]$r.InheritanceFlags)
    if ($r.AccessControlType -eq 'Allow' -and $applies -and ([int]$r.FileSystemRights -band $write) -and $r.IdentityReference.Value -notin $script:trusted) {
      throw "$($r.IdentityReference.Value) can add or replace files in $dir, and $Runner would run what's there as its user. Use a folder only administrators can change."
    }
  }
  # -Contents: what's already inside keeps its own owner and rules, whatever
  # the folder's say, and an owner can always give itself write access back.
  # So a folder whose files get loaded or run must hold nothing of anyone
  # else's: with -Inherited everything below it, and otherwise the files in it
  # that a program loads without being asked. Windows' own folders hold data
  # files that belong to services, which is no reason to refuse them. The
  # folder is held and admin-only by now, so its names stay put while this
  # reads them.
  if ($Contents) {
    $entries = if ($Inherited) { [IO.Directory]::EnumerateFileSystemEntries($dir, '*', [IO.SearchOption]::AllDirectories) } else { [IO.Directory]::EnumerateFiles($dir) }
    foreach ($e in $entries) {
      if (-not $Inherited -and [IO.Path]::GetExtension($e) -notin '.dll', '.exe', '.config', '.manifest', '.local') { continue }
      $es = if ([IO.Directory]::Exists($e)) { [IO.Directory]::GetAccessControl($e, 'Access,Owner') } else { [IO.File]::GetAccessControl($e, 'Access,Owner') }
      $owner = $es.GetOwner([Security.Principal.SecurityIdentifier]).Value
      if ($owner -notin $script:trusted) { throw "$e belongs to $owner, who could change it, and $Runner would run what's in $dir as its user. Change its owner, or use another folder." }
      foreach ($r in $es.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
        if ($r.AccessControlType -eq 'Allow' -and -not ($r.PropagationFlags -band 'InheritOnly') -and ([int]$r.FileSystemRights -band $write) -and $r.IdentityReference.Value -notin $script:trusted) {
          throw "$($r.IdentityReference.Value) can change $e, and $Runner would run what's in $dir as its user"
        }
      }
    }
  }
  if ($Folder) { return }
  # READ_CONTROL and FILE_READ_ATTRIBUTES, without following a link.
  $h = Open-In ([IO.Path]::GetFileName($p)) 0x20080 7
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
