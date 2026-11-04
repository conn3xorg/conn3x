param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module CimCmdlets
# No AD tools: they may not be installed, and the AD drive would reach for ADWS.
# Promotion writes the root domain under NTDS before its reboot, while
# DomainRole changes only with the reboot.
$cs = Get-CimInstance Win32_ComputerSystem
$ntds = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
$root = ''
if ($ntds -and $ntds.'Root Domain') { $root = [string]$ntds.'Root Domain' }
# Left by apply_ad_forest.ps1 (and windows_package), volatile, so gone after a reboot.
$marker = Test-Path -LiteralPath 'HKLM:\SOFTWARE\Conn3x\RebootRequired'
@{ role = [int]$cs.DomainRole; domain = [string]$cs.Domain; root_dn = $root; marker = $marker }
