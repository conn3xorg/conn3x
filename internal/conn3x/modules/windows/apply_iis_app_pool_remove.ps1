param($A)
$config = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (-not (Test-Path -LiteralPath $config)) { return }
[Reflection.Assembly]::Load('Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35') | Out-Null
$sm = [Microsoft.Web.Administration.ServerManager]::new()
$p = $sm.ApplicationPools[$A.name]
if ($p) {
  $sm.ApplicationPools.Remove($p)
  $sm.CommitChanges()
}
