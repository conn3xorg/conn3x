param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$PSModuleAutoLoadingPreference = 'None'
Import-Module NetSecurity
# Only what the step sets: an unset setting is left as it is.
$p = @{ Name = $A.name; ErrorAction = 'Stop' }
if ($null -ne $A.enabled) { $p.Enabled = if ($A.enabled) { 'True' } else { 'False' } }
if ($A.inbound) { $p.DefaultInboundAction = $A.inbound }
if ($A.outbound) { $p.DefaultOutboundAction = $A.outbound }
Set-NetFirewallProfile @p
