param($A)
#include safepath
$path = $A.path
$dir = [IO.Path]::GetDirectoryName($path)
Lock-Folders $dir -Strict:([bool]$A.exact)
$old = Stat-Path $path
if ($old) {
  Assert-NotLink $path $old
  if ($old.Attributes -band 0x10) { throw "$path is a folder" }
  if ($old.Links -gt 1) { throw "$path has other hard links, whose content or access this would change" }
}
$sec = $null
if ($A.exact) { $sec = New-Security ([Security.AccessControl.FileSecurity]) $A.entries }
# The rules are on the temp file from the moment it exists, and nothing else can
# open it before the content is written.
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
  if ($old -and -not $A.exact) {
    # Plain content on a file that's already there keeps its access, unless
    # someone else made the file, whose rules aren't ours to keep.
    $current = [IO.File]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]'Access,Owner')
    if ($current.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $script:trusted) {
      # A descriptor read and written back unchanged wouldn't be saved at all.
      $keep = New-Object Security.AccessControl.FileSecurity
      $keep.SetSecurityDescriptorSddlForm($current.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access), [Security.AccessControl.AccessControlSections]::Access)
      [IO.File]::SetAccessControl($tmp, $keep)
    }
  }
  # REPLACE_EXISTING and WRITE_THROUGH: one step, replacing a name, not following it.
  if (-not [Conn3xFs]::MoveFileExW($tmp, $path, 9)) { throw (New-Object ComponentModel.Win32Exception) }
} finally {
  if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) }
}
