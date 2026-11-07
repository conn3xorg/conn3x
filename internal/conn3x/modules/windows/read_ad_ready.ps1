param($A)
$PSModuleAutoLoadingPreference = 'None'
$env:ADPS_LoadDefaultDrive = 0
# Only a DC has AD to wait for. Anywhere else the OU, group or user read says
# what's wrong, so this answers ready at once.
Import-Module CimCmdlets
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { return '' }
try { Import-Module ActiveDirectory } catch { return '' }
# Straight after a DC's reboot, ADWS can answer for the domain a minute before
# the global catalog, and a write in that minute can hang. So AD is ready once
# a query through the global catalog works too. Anything else is the reason.
try {
  $d = Get-ADDomain
  $gc = Get-ADObject -Server 'localhost:3268' -Identity $d.DistinguishedName
} catch { return [string]$_.Exception.Message }
''
