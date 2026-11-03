param($A)
#include safepath
$config = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (-not (Test-Path -LiteralPath $config)) { throw 'IIS is not installed. Add a windows_feature step for Web-Server before this one.' }
[Reflection.Assembly]::Load('Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35') | Out-Null
$sm = [Microsoft.Web.Administration.ServerManager]::new()
$p = $sm.ApplicationPools[$A.name]
if (-not $p) { $p = $sm.ApplicationPools.Add([string]$A.name) }
elseif ([string]$p.ProcessModel.IdentityType -ne [string]$A.identity) {
  # A new identity runs every site already in the pool, Conn3x's or not, as
  # that account: each of their folders must be admin-only, as for a site step.
  foreach ($s in $sm.Sites) {
    foreach ($app in $s.Applications) {
      if ($app.ApplicationPoolName -ne $A.name) { continue }
      foreach ($v in $app.VirtualDirectories) {
        $vp = [Environment]::ExpandEnvironmentVariables([string]$v.PhysicalPath)
        if (-not [IO.Directory]::Exists($vp)) { throw "site $($s.Name) serves $vp from this pool, which doesn't exist, so Conn3x can't check who can change it" }
        Assert-AdminOnly $vp -Folder -Inherited -Runner "this pool, as $($A.identity),"
      }
    }
  }
}
$p.ManagedRuntimeVersion = [string]$A.runtime
$p.ManagedPipelineMode = [string]$A.pipeline
$p.ProcessModel.IdentityType = [string]$A.identity
$p.AutoStart = [bool]$A.started
$sm.CommitChanges()
# WAS picks up a new pool a moment after the commit, and only then can it start.
$want = $(if ($A.started) { 'Started' } else { 'Stopped' })
for ($i = 0; $i -lt 40; $i++) {
  $p = ([Microsoft.Web.Administration.ServerManager]::new()).ApplicationPools[$A.name]
  $state = 'Unknown'
  try { $state = [string]$p.State } catch { }
  if ($state -eq $want) { return }
  try { if ($A.started) { if ($state -ne 'Starting') { $p.Start() | Out-Null } } elseif ($state -ne 'Stopping') { $p.Stop() | Out-Null } } catch { }
  Start-Sleep -Milliseconds 500
}
throw "app pool $($A.name) is $state, not $want"
