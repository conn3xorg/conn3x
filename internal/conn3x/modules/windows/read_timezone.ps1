param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$current = (Get-TimeZone).Id
# -eq and -contains don't care about case, and nor does Set-TimeZone -Id.
if ($current -eq $A.name) { return @{ current = $current; known = $true } }
$ids = @(Get-TimeZone -ListAvailable | ForEach-Object { [string]$_.Id })
if ($ids -contains $A.name) { return @{ current = $current; known = $true } }
@{ current = $current; known = $false; ids = $ids }
