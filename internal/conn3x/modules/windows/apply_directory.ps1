param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include safepath
$sec = $null
if ($A.exact) { $sec = New-Security ([Security.AccessControl.DirectorySecurity]) $A.entries }
Lock-Folders $A.path -Create -Strict:([bool]$A.exact) -sec $sec
# A folder that was already there still needs its rules. Reapplying them to a
# new one changes nothing.
if ($A.exact) { Set-Rules $script:folder $true $A.entries $true $false $null }
