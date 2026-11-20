param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
$PSModuleAutoLoadingPreference = 'None'
Import-Module CimCmdlets
Import-Module Microsoft.PowerShell.Management
# A domain member's account in AD is renamed too, which may need domain
# credentials; that's refused before this runs, and again here.
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'this host is a domain member; windows_hostname only renames a workgroup host' }
$names = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName'
$running = [string](Get-ItemProperty -LiteralPath "$names\ActiveComputerName").ComputerName
if ($running -eq $A.name) {
  # Asking for the name the host runs under undoes a rename waiting for its
  # reboot. Rename-Computer refuses that ("the new name is the same as the
  # current name"), so the two values it set for the next boot go back.
  Set-ItemProperty -LiteralPath "$names\ComputerName" -Name ComputerName -Value $running -ErrorAction Stop
  Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'NV Hostname' -Value $A.name -ErrorAction Stop
} else {
  # Never -Restart: reboots are their own step, so they show in the plan.
  Rename-Computer -NewName $A.name -Force -ErrorAction Stop -WarningAction SilentlyContinue
}
@{ pending = [string](Get-ItemProperty -LiteralPath "$names\ComputerName").ComputerName }
