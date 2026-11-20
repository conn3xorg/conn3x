param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# An unknown name is an error from DISM; asked quietly, it's nothing.
$f = Get-WindowsOptionalFeature -Online -FeatureName $A.name -ErrorAction SilentlyContinue
if (-not $f) { return @{ exists = $false } }
@{ exists = $true; state = [string]$f.State }
