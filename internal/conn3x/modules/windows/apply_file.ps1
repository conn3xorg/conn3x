param($A)
#include safepath
$path = $A.path
Assert-FullName $path
$dir = [IO.Path]::GetDirectoryName($path)
Lock-Folders $dir -Strict:([bool]$A.exact)
$old = $null
$sec = $null
$keep = $null # a plain rewrite's rules to restore after writing, when it may inherit
if ($A.exact) { $sec = New-Security ([Security.AccessControl.FileSecurity]) $A.entries }
$h = Open-NoFollow $path 0x20080 7
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
$tmp = [IO.Path]::Combine($dir, '.conn3x-' + [guid]::NewGuid().ToString('N') + '.tmp')
$stream = New-Object IO.FileStream($tmp, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]'Write,Read', [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, $sec)
try {
  try {
    # An empty folder could have become a junction before the temp file made it non-empty.
    Assert-NotLink $dir (Stat-Path $dir)
    $bytes = [Convert]::FromBase64String($A.content)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  } finally { $stream.Dispose() }
  if ($keep) {
    # Let the system apply the inheriting rules, so it marks the DACL
    # auto-inherited as the original file was. Through a handle, not the name.
    $th = Open-NoFollow $tmp 0x60080 7 # READ_CONTROL, WRITE_DAC, FILE_READ_DATA
    try {
      $fs = New-Object Security.AccessControl.FileSecurity
      $fs.SetSecurityDescriptorSddlForm($keep, [Security.AccessControl.AccessControlSections]::Access)
      $raw = New-Object Security.AccessControl.RawSecurityDescriptor($fs.GetSecurityDescriptorBinaryForm(), 0)
      $dacl = New-Object byte[] $raw.DiscretionaryAcl.BinaryLength
      $raw.DiscretionaryAcl.GetBinaryForm($dacl, 0)
      # DACL plus UNPROTECTED_DACL, so Windows recomputes auto-inheritance. 1 is SE_FILE_OBJECT.
      $code = [Conn3xFs]::SetSecurityInfo($th, 1, [uint32]536870916, $null, $null, $dacl, $null)
      if ($code) { throw (New-Object ComponentModel.Win32Exception ([int]$code)) }
    } finally { $th.Dispose() }
  }
  # REPLACE_EXISTING and WRITE_THROUGH: one step, replacing a name, not following it.
  if (-not [Conn3xFs]::MoveFileExW($tmp, $path, 9)) { throw (New-Object ComponentModel.Win32Exception) }
} finally {
  if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) }
}
