param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# Runs choco.exe from the machine's ChocolateyInstall, with each value its
# own argument, never a command line made from strings.
$root = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
$choco = $root + '\choco.exe'
if (-not $root -or -not (Test-Path -LiteralPath $choco -PathType Leaf)) { throw 'Chocolatey isn''t installed: the machine has no ChocolateyInstall variable, or no choco.exe under it' }
$script:restart = $false
function Invoke-Choco([string[]]$arguments) {
  $output = & $choco @arguments --no-progress --limit-output 2>&1 | Out-String
  # 3010 and 1641: done, and Windows wants a reboot, which windows_reboot does.
  if ($LASTEXITCODE -in 3010, 1641) { $script:restart = $true }
  elseif ($LASTEXITCODE -ne 0) {
    $tail = ($output.Trim() -split "`r?`n" | Select-Object -Last 15) -join "`n"
    throw "choco $($arguments[0]) $($arguments[1]) exited $($LASTEXITCODE):`n$tail"
  }
}
$name = [string]$A.name
# choco skips a pinned package, exiting 0, so its pin comes off first.
if ($A.unpin_first) { Invoke-Choco @('pin', 'remove', '-n', $name) }
if ($A.remove) { Invoke-Choco @('uninstall', $name, '-y') }
if ($A.install) {
  # upgrade installs a package that isn't there, and with a version and
  # --allow-downgrade, moves an installed one to exactly that version.
  $arguments = @('upgrade', $name, '-y')
  if ($A.version) { $arguments += @('--version', [string]$A.version, '--allow-downgrade') }
  if ($A.source) { $arguments += @('--source', [string]$A.source) }
  Invoke-Choco $arguments
}
if ($A.pin) { Invoke-Choco @('pin', [string]$A.pin, '-n', $name) }
@{ restart = $script:restart }
