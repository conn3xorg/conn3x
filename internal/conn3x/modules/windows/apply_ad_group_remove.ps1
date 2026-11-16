param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#include ad
Import-AD
$g = Get-ADGroup -Identity ([string]$A.dn)
if ((Get-LoginSIDs) -contains $g.SID.Value) { throw "the login Conn3x uses gets its rights through $($g.Name); deleting it could lock Conn3x out" }
Remove-ADGroup -Identity $g -Confirm:$false
