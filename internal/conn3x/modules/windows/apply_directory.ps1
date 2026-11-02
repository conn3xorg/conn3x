param($A)
#include safepath
$sec = $null
if ($A.exact) { $sec = New-Security ([Security.AccessControl.DirectorySecurity]) $A.entries }
Lock-Folders $A.path -Create -Strict:([bool]$A.exact) -sec $sec
# A folder that was already there still needs its rules. Reapplying them to a
# new one changes nothing.
if ($A.exact) { Set-Rules $A.path $true $A.entries $true $false $null }
