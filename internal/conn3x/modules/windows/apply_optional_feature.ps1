param($A)
# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
# Always -NoRestart: reboots are their own step, so they show in the plan.
$p = @{ Online = $true; FeatureName = $A.name; NoRestart = $true; ErrorAction = 'Stop' }
if ($A.present) {
  if ($A.include_parent) { $p.All = $true }
  if ($A.source) { $p.Source = $A.source }
  $r = Enable-WindowsOptionalFeature @p
} else {
  $r = Disable-WindowsOptionalFeature @p
}
@{ restart = [bool]$r.RestartNeeded }
