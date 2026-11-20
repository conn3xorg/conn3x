param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include lsawrite
# Leaving the login Conn3x uses without a logon right it had, or giving it a
# deny-logon right, could lock Conn3x out, whether through its own SID or a
# group's, such as Administrators. Narrowing a right is fine while the login
# keeps it through a SID that stays.
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$mine = @($id.User.Value) + @($id.Groups | ForEach-Object { $_.Value })
$logon = 'SeNetworkLogonRight', 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight', 'SeBatchLogonRight', 'SeServiceLogonRight'
$had = @(@($A.holders) | Where-Object { $mine -contains $_ })
$left = @(@($A.holders) + @($A.add) | Where-Object { $mine -contains $_ -and @($A.remove) -notcontains $_ })
if ($A.name -in $logon -and $had.Count -gt 0 -and $left.Count -eq 0) {
  throw "this would take $($A.name) from $($had -join ', '), the login Conn3x uses has it through no one else, and that could lock Conn3x out"
}
if ($A.name -like 'SeDeny*LogonRight') {
  foreach ($s in @($A.add)) {
    if ($mine -contains $s) { throw "this would give $s $($A.name), and the login Conn3x uses gets its rights through it; that could lock Conn3x out" }
  }
}
[Conn3xLsaWrite]::Change([string]$A.name, [string[]]@($A.add | Where-Object { $_ }), [string[]]@($A.remove | Where-Object { $_ }))
