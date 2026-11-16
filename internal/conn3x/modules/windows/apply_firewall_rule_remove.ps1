param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$r = @(Get-NetFirewallRule -Name $A.name -ErrorAction SilentlyContinue)
if ($r.Count) { Remove-NetFirewallRule -InputObject $r[0] }
