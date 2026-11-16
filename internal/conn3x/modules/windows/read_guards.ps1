param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
if ($A.creates -and -not (Test-Path -LiteralPath $A.creates)) { return $false }
if ($A.removes -and (Test-Path -LiteralPath $A.removes)) { return $false }
$true
