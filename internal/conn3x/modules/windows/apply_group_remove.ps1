param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$g = Get-LocalGroup -Name $A.name -ErrorAction SilentlyContinue
if ($g) { Remove-LocalGroup -InputObject $g }
