# Runs once on first boot, through the Custom Script Extension. It gets the
# host's private key from the extension's protected settings, by way of an
# environment variable, and the public keys from its own text, which Conn3x
# fills in. It never logs a key.
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
[IO.File]::WriteAllBytes($key, [Convert]::FromBase64String($env:CONN3X_HOST_KEY))
[IO.File]::WriteAllText("$key.pub", "__HOST_PUB__`n")
$admins = "$d\administrators_authorized_keys"
[IO.File]::WriteAllText($admins, "__ADMIN_PUB__`n")
foreach ($f in $key, $admins) {
  # SIDs, because group names change with the display language.
  & icacls.exe $f /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F' | Out-Null
  if ($LASTEXITCODE) { throw "icacls failed on $f with $LASTEXITCODE" }
}

# Keys only, from here on.
$config = "$d\sshd_config"
$text = [IO.File]::ReadAllText($config) -replace '(?m)^#?PasswordAuthentication .*$', 'PasswordAuthentication no'
[IO.File]::WriteAllText($config, $text)

if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
Set-Service sshd -StartupType Automatic
Start-Service sshd
