param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include safepath
Assert-FullName $A.path
Lock-Folders ([IO.Path]::GetDirectoryName($A.path))
# Opened in the held folder with DELETE, and deleted through that handle. The
# name isn't looked up a second time: by then it could lead somewhere else.
$h = Open-In ([IO.Path]::GetFileName($A.path)) 0x10080 7
if (-not $h) { return }
try {
  $i = Get-Info $h
  $isLink = $i.Attributes -band 0x400
  if (($i.Attributes -band 0x10) -and -not $isLink) { throw "$($A.path) is a folder" }
  # A link goes, not what it points to. Removing a junction leaves its target alone.
  [Conn3xFs]::Remove($h)
} finally { $h.Dispose() }
