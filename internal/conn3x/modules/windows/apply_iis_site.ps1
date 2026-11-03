param($A)
#include safepath
$config = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (-not (Test-Path -LiteralPath $config)) { throw 'IIS is not installed. Add a windows_feature step for Web-Server before this one.' }
[Reflection.Assembly]::Load('Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35') | Out-Null
$path = [string]$A.physical_path
# The pool runs what's in the folder, and any pool identity can get to SYSTEM
# through its impersonation right, so only administrators may change it.
if (-not [IO.Directory]::Exists($path)) { throw "physical_path $path doesn't exist. Make it first, writable by administrators only, so Conn3x can check who can change it." }
Assert-AdminOnly $path -Folder -Inherited -Runner "the site's app pool"
$sm = [Microsoft.Web.Administration.ServerManager]::new()
$bindings = @($A.bindings)
$s = $sm.Sites[$A.name]
if (-not $s) { $s = $sm.Sites.Add([string]$A.name, [string]$bindings[0].protocol, [string]$bindings[0].information, [string]$A.physical_path) }
$s.Bindings.Clear()
foreach ($b in $bindings) { $s.Bindings.Add([string]$b.information, [string]$b.protocol) | Out-Null }
$app = $s.Applications['/']
if (-not $app) { $app = $s.Applications.Add('/', [string]$A.physical_path) }
$vdir = $app.VirtualDirectories['/']
if (-not $vdir) { throw "site $($A.name) has a root application with no / virtual directory. Fix or delete the site by hand first." }
$vdir.PhysicalPath = [string]$A.physical_path
if ($null -ne $A.app_pool) {
  if (-not $sm.ApplicationPools[$A.app_pool]) { throw "app pool $($A.app_pool) doesn't exist. Add a windows_iis_app_pool step for it before this one." }
  $app.ApplicationPoolName = [string]$A.app_pool
}
$s.ServerAutoStart = [bool]$A.started
$sm.CommitChanges()
# As for pools: WAS takes a moment to see a new site.
$want = $(if ($A.started) { 'Started' } else { 'Stopped' })
$why = ''
for ($i = 0; $i -lt 40; $i++) {
  $s = ([Microsoft.Web.Administration.ServerManager]::new()).Sites[$A.name]
  $state = 'Unknown'
  try { $state = [string]$s.State } catch { }
  if ($state -eq $want) { return }
  try { if ($A.started) { if ($state -ne 'Starting') { $s.Start() | Out-Null } } elseif ($state -ne 'Stopping') { $s.Stop() | Out-Null } } catch { $why = $_.Exception.Message }
  Start-Sleep -Milliseconds 500
}
# Most often another site already has the binding.
throw "site $($A.name) is $state, not $want. $why"
