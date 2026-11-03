param($A)
$PSModuleAutoLoadingPreference = 'None'
# As read_iis_app_pool.ps1: read-only Microsoft.Web.Administration, no IIS: drive.
$config = $env:windir + '\System32\inetsrv\config\applicationHost.config'
if (-not (Test-Path -LiteralPath $config)) { return @{ installed = $false; exists = $false } }
try { $null = [Reflection.Assembly]::Load('Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35') }
catch { return @{ installed = $false; exists = $false } }
$sm = [Microsoft.Web.Administration.ServerManager]::new($true, $config)
$s = $sm.Sites[$A.name]
if (-not $s) { return @{ installed = $true; exists = $false } }
$state = 'Unknown'
try { $state = [string]$s.State } catch { }
$app = $s.Applications['/']
$path = ''; $pool = ''
if ($app) {
  $pool = [string]$app.ApplicationPoolName
  $vdir = $app.VirtualDirectories['/']
  if ($vdir) { $path = [string]$vdir.PhysicalPath }
}
@{ installed = $true; exists = $true; state = $state; auto_start = [bool]$s.ServerAutoStart; physical_path = $path; app_pool = $pool
   bindings = @($s.Bindings | Where-Object { $_ } | ForEach-Object { @{ protocol = [string]$_.Protocol; information = [string]$_.BindingInformation } }) }
