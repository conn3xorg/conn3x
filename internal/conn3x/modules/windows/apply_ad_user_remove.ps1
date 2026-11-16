param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include ad
Import-AD
$u = Get-ADUser -Identity ([string]$A.dn)
if ($u.SID.Value -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw "$($u.Name) is the user Conn3x logs in as; deleting it would lock Conn3x out of the host" }
Remove-ADUser -Identity $u -Confirm:$false
