param($A)
$PSModuleAutoLoadingPreference = 'None'
# The names conn3x generate steps lists for a kind, sorted by the caller.
switch ([string]$A.kind) {
  'features' {
    Import-Module ServerManager
    $names = @(Get-WindowsFeature | Where-Object Installed | ForEach-Object { [string]$_.Name })
  }
  'services' {
    Import-Module Microsoft.PowerShell.Management
    $names = @(Get-Service | ForEach-Object { [string]$_.Name })
  }
  { $_ -in 'users', 'groups' } {
    # A domain controller has no local accounts, and these cmdlets say so
    # with an error a person can't act on.
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
      throw "this host is a domain controller, which has no local $($A.kind); list the domain's with Get-ADUser or Get-ADGroup"
    }
    Import-Module Microsoft.PowerShell.LocalAccounts
    if ($A.kind -eq 'users') {
      $names = @(Get-LocalUser | ForEach-Object { [string]$_.Name })
    } else {
      $names = @(Get-LocalGroup | ForEach-Object { [string]$_.Name })
    }
  }
  default { throw "unknown kind $($A.kind)" }
}
@{ names = $names }
