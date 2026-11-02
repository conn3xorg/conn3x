param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module ScheduledTasks
$out = @{ exists = $false; want_sid = ''; user_sid = '' }
try {
  if ($A.user -match '^S-1-[0-9-]+$') { $out.want_sid = ([Security.Principal.SecurityIdentifier]$A.user).Value }
  else { $out.want_sid = ([Security.Principal.NTAccount]$A.user).Translate([Security.Principal.SecurityIdentifier]).Value }
} catch { $out.want_sid = '' }
# The name and folder were checked for wildcards before they got here.
$t = Get-ScheduledTask -TaskPath $A.path -TaskName $A.name -ErrorAction SilentlyContinue
if (-not $t) { return $out }
$out.exists = $true
$out.description = [string]$t.Description
$out.enabled = ($t.Settings.Enabled -eq $true)
# Where-Object first: $null down a pipeline still runs ForEach-Object once.
$out.actions = @($t.Actions | Where-Object { $_ } | ForEach-Object { @{ execute = [string]$_.Execute; arguments = [string]$_.Arguments; working_directory = [string]$_.WorkingDirectory } })
$out.triggers = @($t.Triggers | Where-Object { $_ } | ForEach-Object { @{ kind = [string]$_.CimClass.CimClassName; start = [string]$_.StartBoundary; days = [int]$_.DaysInterval; enabled = [bool]$_.Enabled } })
$out.logon = [string]$t.Principal.LogonType
$out.run_level = [string]$t.Principal.RunLevel
$u = [string]$t.Principal.UserId
try {
  if ($u -match '^S-1-[0-9-]+$') { $out.user_sid = ([Security.Principal.SecurityIdentifier]$u).Value }
  else { $out.user_sid = ([Security.Principal.NTAccount]$u).Translate([Security.Principal.SecurityIdentifier]).Value }
} catch { $out.user_sid = '' }
$out
