param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# Always -NoRestart: reboots are their own step, so they show in the plan.
$p = @{ Online = $true; FeatureName = $A.name; NoRestart = $true; ErrorAction = 'Stop' }
if ($A.present) {
  if ($A.include_parent) { $p.All = $true }
  if ($A.source) {
    # As Ansible does, a folder or share that isn't there fails with that,
    # not with DISM's error. A wim: or esd: source names an image's index,
    # which Test-Path can't read, so DISM checks those itself.
    if ($A.source -notmatch '^(wim|esd):' -and -not (Test-Path -LiteralPath $A.source)) { throw "source $($A.source) could not be found" }
    $p.Source = $A.source
  }
  $r = Enable-WindowsOptionalFeature @p
} else {
  $r = Disable-WindowsOptionalFeature @p
}
@{ restart = [bool]$r.RestartNeeded }
