param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include safepath
#include download
# Written the way apply_file.ps1 writes a file without exact rules: into a temp
# file in the held folder, renamed over dest in one step, never following a
# link, and keeping an existing file's access. The download goes into the temp
# file and its hash is checked before the rename, so dest is never a partial
# or mismatched download, not even for a moment.
$path = $A.path
Assert-FullName $path
$dir = [IO.Path]::GetDirectoryName($path)
Lock-Folders $dir
$keep = $null
$sec = $null
$leaf = [IO.Path]::GetFileName($path)
$h = Open-In $leaf 0x20080 7
if ($h) {
  try {
    $old = Get-Info $h
    Assert-NotLink $path $old
    if ($old.Attributes -band 0x10) { throw "$path is a folder" }
    if ($old.Links -gt 1) { throw "$path has other hard links, whose content this would change" }
    # As in apply_file.ps1: a file we or the system own keeps its rules; one
    # restricted from birth gets them on the temp file before any content.
    $current = Read-Security $h ([Security.AccessControl.FileSecurity]) 5
    if ($current.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $script:trusted) {
      $keep = $current.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
      if ($current.AreAccessRulesProtected) {
        $sec = New-Object Security.AccessControl.FileSecurity
        $sec.SetSecurityDescriptorSddlForm($keep, [Security.AccessControl.AccessControlSections]::Access)
        $keep = $null
      }
    }
  } finally { $h.Dispose() }
}
$sd = $null
if ($sec) { $sd = $sec.GetSecurityDescriptorBinaryForm() }
# FILE_GENERIC_READ and FILE_GENERIC_WRITE, DELETE and WRITE_DAC, no sharing,
# FILE_CREATE, FILE_WRITE_THROUGH and FILE_NON_DIRECTORY_FILE, as apply_file.ps1.
$th = [Conn3xFs]::OpenIn($script:folder, '.conn3x-' + [guid]::NewGuid().ToString('N') + '.tmp', 0x17019F, 0, 2, 0x42, $sd)
$stream = New-Object IO.FileStream($th, [IO.FileAccess]::ReadWrite)
try {
  try {
    Save-Download ([string]$A.url) $stream ([long]$A.max_bytes) ([bool]$A.allow_http)
    $stream.Flush($true)
    $stream.Position = 0
    $sum = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    if ($sum -ne $A.sha256) { throw "the download's SHA-256 is $sum, not $($A.sha256) as configured; $path was left as it was" }
    if ($keep) {
      $fs = New-Object Security.AccessControl.FileSecurity
      $fs.SetSecurityDescriptorSddlForm($keep, [Security.AccessControl.AccessControlSections]::Access)
      $raw = New-Object Security.AccessControl.RawSecurityDescriptor($fs.GetSecurityDescriptorBinaryForm(), 0)
      $dacl = New-Object byte[] $raw.DiscretionaryAcl.BinaryLength
      $raw.DiscretionaryAcl.GetBinaryForm($dacl, 0)
      # DACL plus UNPROTECTED_DACL, so Windows recomputes auto-inheritance. 1 is SE_FILE_OBJECT.
      $code = [Conn3xFs]::SetSecurityInfo($th, 1, [uint32]536870916, $null, $null, $dacl, $null)
      if ($code) { throw (New-Object ComponentModel.Win32Exception ([int]$code)) }
    }
    # One step, replacing a name, not following it.
    [Conn3xFs]::RenameTo($th, $leaf)
  } catch {
    [Conn3xFs]::Remove($th)
    throw
  }
} finally { $stream.Dispose() }
@{ sha256 = $sum }
