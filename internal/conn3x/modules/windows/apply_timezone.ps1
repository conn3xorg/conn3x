param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
Set-TimeZone -Id $A.name -ErrorAction Stop
@{ current = (Get-TimeZone).Id }
