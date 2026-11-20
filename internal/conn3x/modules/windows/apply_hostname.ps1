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
  # current name"), so it goes through Win32_ComputerSystem.Rename, Windows'
  # own rename, which sets everything a rename sets for the next boot.
  $r = Invoke-CimMethod -InputObject (Get-CimInstance Win32_ComputerSystem) -MethodName Rename -Arguments @{ Name = $A.name } -ErrorAction Stop
  if ($r.ReturnValue -ne 0) { throw "Win32_ComputerSystem.Rename returned $($r.ReturnValue)" }
} else {
  # Never -Restart: reboots are their own step, so they show in the plan.
  Rename-Computer -NewName $A.name -Force -ErrorAction Stop -WarningAction SilentlyContinue
}
@{ pending = [string](Get-ItemProperty -LiteralPath "$names\ComputerName").ComputerName }
