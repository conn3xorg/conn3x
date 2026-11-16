param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($A.key, $true)
if (-not $key) { return }
try { $key.DeleteValue($A.name, $false) } finally { $key.Close() }
