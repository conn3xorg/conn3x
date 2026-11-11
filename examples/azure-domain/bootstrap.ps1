# Runs once on first boot. load-bootstrap.ps1 runs it from the Custom Script
# Extension's protected settings, which Windows holds encrypted. It reads the
# host's private key from the same settings, so the key is never on a command
# line, and the public keys from its own text, which Conn3x fills in. It never
# logs a key.
$ErrorActionPreference = 'Stop'

$d = 'C:\ProgramData\ssh'
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
  # Server 2022 and earlier don't have it until it's added.
  Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
[void][IO.Directory]::CreateDirectory($d)

# Conn3x installs its own host key, so it can check the host from the first
# connection. Only this key stays; sshd makes any other type it wants for itself.
Stop-Service sshd -ErrorAction SilentlyContinue
Remove-Item "$d\ssh_host_rsa_key*", "$d\ssh_host_ecdsa_key*" -Force -ErrorAction SilentlyContinue
$key = "$d\ssh_host_ed25519_key"
$admins = "$d\administrators_authorized_keys"

# A .NET parser, not ConvertFrom-Json: a policy can log a cmdlet's parameters.
function Read-HostKey {
  Add-Type -AssemblyName System.Security, System.Web.Extensions
  $js = New-Object Web.Script.Serialization.JavaScriptSerializer
  $file = Get-ChildItem 'C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\*\RuntimeSettings\*.settings' | Sort-Object LastWriteTimeUtc | Select-Object -Last 1
  $handler = $js.DeserializeObject([IO.File]::ReadAllText($file.FullName))['runtimeSettings'][0]['handlerSettings']
  $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
  $store.Open('ReadOnly')
  $cert = $store.Certificates.Find('FindByThumbprint', $handler['protectedSettingsCertThumbprint'], $false)
  $cms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
  $cms.Decode([Convert]::FromBase64String($handler['protectedSettings']))
  $cms.Decrypt($cert)
  $js.DeserializeObject([Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content))['conn3xHostKey']
}

# The rules are on the file from the moment it exists. SIDs, because group names
# change with the display language.
function New-LockedFile([string]$path, [byte[]]$bytes) {
  if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
  $sec = New-Object Security.AccessControl.FileSecurity
  $sec.SetAccessRuleProtection($true, $false)
  foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $who = New-Object Security.Principal.SecurityIdentifier $sid
    $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'Allow')))
  }
  $s = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]'Write,Read', [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough, $sec)
  try { $s.Write($bytes, 0, $bytes.Length) } finally { $s.Dispose() }
}

$hostKey = Read-HostKey
if (-not $hostKey) { throw 'the protected settings hold no host key' }
New-LockedFile $key ([Convert]::FromBase64String($hostKey))
[IO.File]::WriteAllText("$key.pub", "__HOST_PUB__`n")
New-LockedFile $admins ([Text.Encoding]::ASCII.GetBytes("__ADMIN_PUB__`n"))

# Keys only, from here on.
$config = "$d\sshd_config"
# On Server 2022, sshd writes this from its default at first start, which hasn't happened yet.
if (-not [IO.File]::Exists($config)) {
  Copy-Item "$env:WINDIR\System32\OpenSSH\sshd_config_default" $config
}
$text = [IO.File]::ReadAllText($config) -replace '(?m)^#?PasswordAuthentication .*$', 'PasswordAuthentication no'
[IO.File]::WriteAllText($config, $text)

if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
