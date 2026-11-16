param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include safepath
$path = $A.path
Assert-FullName $path
$dir = [IO.Path]::GetDirectoryName($path)
Lock-Folders $dir -Strict:([bool]$A.exact)
$old = $null
$sec = $null
$keep = $null # a plain rewrite's rules to restore after writing, when it may inherit
if ($A.exact) { $sec = New-Security ([Security.AccessControl.FileSecurity]) $A.entries }
$leaf = [IO.Path]::GetFileName($path)
$h = Open-In $leaf 0x20080 7
if ($h) {
  try {
    $old = Get-Info $h
    Assert-NotLink $path $old
    if ($old.Attributes -band 0x10) { throw "$path is a folder" }
    if ($old.Links -gt 1) { throw "$path has other hard links, whose content or access this would change" }
    # Plain content on a file that's already there keeps its access, unless
    # someone else made the file, whose rules aren't ours to keep.
    if (-not $A.exact) {
      $current = Read-Security $h ([Security.AccessControl.FileSecurity]) 5
      if ($current.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $script:trusted) {
        $keep = $current.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        # A restricted file gets its rules from birth: the temp must never sit
        # under the folder's looser rules with the new content in it. A file
        # that only inherits can't leak more than the folder already does, so it
        # takes the folder's rules now and the exact ones (auto-inherit and all)
        # once written.
        if ($current.AreAccessRulesProtected) {
          $sec = New-Object Security.AccessControl.FileSecurity
          $sec.SetSecurityDescriptorSddlForm($keep, [Security.AccessControl.AccessControlSections]::Access)
          $keep = $null
        }
      }
    }
  } finally { $h.Dispose() }
}
# The temp file has its final rules from the moment it exists, or the folder's
# when a new file should simply inherit, and nothing else can open it while the
# content is written. Rules set later would leave a restricted file's content
# open to whoever can read the folder until then.
#
# One handle makes the temp file in the held folder, writes it, sets its rules,
# renames it into place and, on failure, deletes it. Its name is never looked up
# again: whoever can delete in the folder could otherwise empty it once the file
# was closed, turn it into a junction, and have the rename or the clean-up land
# wherever that points.
$sd = $null
if ($sec) { $sd = $sec.GetSecurityDescriptorBinaryForm() }
# FILE_GENERIC_READ and FILE_GENERIC_WRITE, DELETE to rename or remove it, and
# WRITE_DAC. No sharing. FILE_CREATE, so a file someone put at that name is
# never taken for ours; FILE_WRITE_THROUGH and FILE_NON_DIRECTORY_FILE.
$th = [Conn3xFs]::OpenIn($script:folder, '.conn3x-' + [guid]::NewGuid().ToString('N') + '.tmp', 0x17019F, 0, 2, 0x42, $sd)
$stream = New-Object IO.FileStream($th, [IO.FileAccess]::ReadWrite)
try {
  try {
    $bytes = [Convert]::FromBase64String($A.content)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
    if ($keep) {
      # Let the system apply the inheriting rules, so it marks the DACL
      # auto-inherited as the original file was.
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
