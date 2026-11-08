param($A)
# Windows Update only installs for a local login, so a one-off scheduled task
# runs the worker as SYSTEM and this waits for its result. The folder is new
# under the Windows folder, where only administrators can create anything and
# users can't write, so nothing can be swapped in before SYSTEM runs it.
$worker = @'
#include updateworker
'@
$dir = Join-Path $env:SystemRoot ('Conn3x-updates-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($dir)
$ps1 = Join-Path $dir 'worker.ps1'
$in = Join-Path $dir 'in.json'
$out = Join-Path $dir 'out.json'
$name = [IO.Path]::GetFileName($dir)
try {
  [IO.File]::WriteAllText($ps1, $worker)
  [IO.File]::WriteAllText($in, (@{ categories = @($A.categories); accept = @($A.accept); reject = @($A.reject) } | ConvertTo-Json -Compress))
  $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $action = New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -In "{1}" -Out "{2}"' -f $ps1, $in, $out)
  $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
  $limit = [TimeSpan]::FromSeconds([int]$A.timeout_seconds)
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit $limit -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -TaskPath '\Conn3x\' -Action $action -Principal $principal -Settings $settings | Out-Null
  Start-ScheduledTask -TaskName $name -TaskPath '\Conn3x\'
  $deadline = (Get-Date).Add($limit)
  while (-not [IO.File]::Exists($out)) {
    if ((Get-Date) -gt $deadline) { throw ('Windows Update had not finished after ' + [int]$limit.TotalMinutes + ' minutes; raise timeout, or check the host') }
    Start-Sleep -Seconds 5
    $task = Get-ScheduledTask -TaskName $name -TaskPath '\Conn3x\'
    if ($task.State -ne 'Running' -and -not [IO.File]::Exists($out)) {
      Start-Sleep -Seconds 2
      if (-not [IO.File]::Exists($out)) {
        $info = Get-ScheduledTaskInfo -TaskName $name -TaskPath '\Conn3x\'
        throw ('the update task stopped without a result (last result ' + $info.LastTaskResult + ')')
      }
    }
  }
  $res = [IO.File]::ReadAllText($out) | ConvertFrom-Json
  if (-not $res.ok) { throw ('Windows Update: ' + $res.error) }
  @{ installed = @($res.installed); failed = @($res.failed); restart = [bool]$res.reboot }
} finally {
  Unregister-ScheduledTask -TaskName $name -TaskPath '\Conn3x\' -Confirm:$false -ErrorAction SilentlyContinue
  [IO.Directory]::Delete($dir, $true)
}
