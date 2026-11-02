param($A)
$s = Get-Service -Name $A.name
if ($A.start_mode) {
  # sc.exe, since Set-Service in this PowerShell can't set delayed start. The
  # name was checked against a list of safe characters before it got here.
  $mode = @{ auto = 'auto'; delayed = 'delayed-auto'; manual = 'demand'; disabled = 'disabled' }[[string]$A.start_mode]
  if (-not $mode) { throw "unknown start mode $($A.start_mode)" }
  $out = & "$env:WINDIR\System32\sc.exe" config $s.ServiceName start= $mode 2>&1
  if ($LASTEXITCODE) { throw "sc.exe exited with ${LASTEXITCODE}: $out" }
}
if ($A.state -eq 'running') { Start-Service -InputObject $s }
if ($A.state -eq 'stopped') { Stop-Service -InputObject $s }
$global:LASTEXITCODE = 0
