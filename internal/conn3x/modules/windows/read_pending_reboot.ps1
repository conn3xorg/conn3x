param($A)
# Windows servicing (TrustedInstaller) sets RebootPending while it works
# and often clears it when it's done: after a domain join or a promotion it
# ran about twelve minutes after boot and had the key up for two and a half
# minutes, with nothing waiting for a reboot after. So while servicing runs,
# wait for it to settle, for up to three minutes, inside the read's five. If
# it's still at it then, the key counts.
$cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$waits = 0
while ((Test-Path -LiteralPath $cbs) -and (Get-Service -Name TrustedInstaller).Status -eq 'Running' -and $waits -lt 18) {
  Start-Sleep -Seconds 10
  $waits++
}
$session = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
$active = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -ErrorAction SilentlyContinue
$next = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -ErrorAction SilentlyContinue
[bool]((Test-Path -LiteralPath $cbs) -or
  (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
  # Set by windows_package, and volatile, so the next boot clears it.
  (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Conn3x\RebootRequired') -or
  ($session -and $session.PendingFileRenameOperations) -or
  ($active -and $next -and $active.ComputerName -ne $next.ComputerName))
