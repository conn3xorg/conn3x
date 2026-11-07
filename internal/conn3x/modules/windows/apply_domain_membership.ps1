param($A)
#include ad
# The password becomes a SecureString through .NET, as in apply_ad_forest.ps1.
# A key login has no credentials of its own to reach the domain with, so the
# account to join with is given explicitly.
$set = @{
  DomainName = [string]$A.domain
  Credential = [Management.Automation.PSCredential]::new([string]$A.username, [Net.NetworkCredential]::new('', [string]$A.password).SecurePassword)
}
if ($A.ou) { $set.OUPath = [string]$A.ou }
# Never -Restart: the reboot is its own step, so it shows in the plan.
Add-Computer @set -Force -Confirm:$false -WarningAction SilentlyContinue
Set-RebootMarker
@{ restart = $true }
