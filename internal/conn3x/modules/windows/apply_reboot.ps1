param($A)
# Five seconds, so this returns and reports before the connection drops.
& "$env:WINDIR\System32\shutdown.exe" /r /t 5 /d p:0:0 /c 'conn3x windows_reboot'
if ($LASTEXITCODE) { throw "shutdown.exe exited with $LASTEXITCODE" }
$global:LASTEXITCODE = 0
