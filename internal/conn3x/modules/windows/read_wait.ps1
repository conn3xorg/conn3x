param($A)
if ($A.path) { return [bool](Test-Path -LiteralPath $A.path) }
if ($A.service) {
  $s = Get-Service -Name $A.service -ErrorAction SilentlyContinue
  return [bool]($s -and $s.Status -eq 'Running')
}
$PSModuleAutoLoadingPreference = 'None'
Import-Module NetTCPIP
[bool](Get-NetTCPConnection -State Listen -LocalPort ([int]$A.port) -ErrorAction SilentlyContinue)
