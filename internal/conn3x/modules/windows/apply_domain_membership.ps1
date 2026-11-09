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
try { Add-Computer @set -Force -Confirm:$false -WarningAction SilentlyContinue }
catch {
  # Seen on Azure: a missing OU comes back as "The system cannot find the file
  # specified", which names neither the OU nor the cause.
  if ($A.ou -and $_.Exception.Message -match 'cannot find the file specified') {
    throw "the OU $($A.ou) wasn't found, or $($A.username) can't see it. Make it first, as with a windows_ad_ou step. Windows said: $($_.Exception.Message)"
  }
  throw
}
Set-RebootMarker
@{ restart = $true }
