param($A)
$PSModuleAutoLoadingPreference = 'None'
# Microsoft.Web.Administration, opened read-only, reads applicationHost.config
# and asks WAS for the state; no IIS: drive, which can change things on first use.
$config = $env:windir + '\System32\inetsrv\config\applicationHost.config'
if (-not (Test-Path -LiteralPath $config)) { return @{ installed = $false; exists = $false } }
try { $null = [Reflection.Assembly]::Load('Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35') }
catch { return @{ installed = $false; exists = $false } }
$sm = [Microsoft.Web.Administration.ServerManager]::new($true, $config)
# The name was checked for wildcards before it got here; the lookup is exact anyway.
$p = $sm.ApplicationPools[$A.name]
if (-not $p) { return @{ installed = $true; exists = $false } }
$state = 'Unknown'
try { $state = [string]$p.State } catch { }
@{ installed = $true; exists = $true; state = $state; auto_start = [bool]$p.AutoStart; runtime = [string]$p.ManagedRuntimeVersion
   pipeline = [string]$p.ManagedPipelineMode; identity = [string]$p.ProcessModel.IdentityType }
