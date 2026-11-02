param($A)
$PSModuleAutoLoadingPreference = 'None'
Import-Module CimCmdlets, NetTCPIP
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$nt = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
$ipv4 = ''
if ($route) {
  $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($ip) { $ipv4 = $ip.IPAddress }
}
@{
  version           = [string]$os.Version
  product_type      = [int]$os.ProductType
  build             = [string]$os.BuildNumber
  arch              = [string]$env:PROCESSOR_ARCHITECTURE
  cpus              = [int]$cs.NumberOfLogicalProcessors
  memory_kb         = [int64]$os.TotalVisibleMemorySize
  ipv4              = [string]$ipv4
  edition           = [string]$nt.EditionID
  installation_type = [string]$nt.InstallationType
  hostname          = [string]$cs.DNSHostName
  domain            = [string]$cs.Domain
  domain_role       = [int]$cs.DomainRole
  powershell        = $PSVersionTable.PSVersion.ToString()
  elevated          = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
