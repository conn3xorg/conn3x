param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$PSModuleAutoLoadingPreference = 'None'
Import-Module CimCmdlets
# The running name, and the one a rename has set for the next boot. They
# differ only between Rename-Computer and the reboot.
$running = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
$pending = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
$cs = Get-CimInstance Win32_ComputerSystem
@{ running = $running; pending = $pending; domain_member = [bool]$cs.PartOfDomain; domain = [string]$cs.Domain }
