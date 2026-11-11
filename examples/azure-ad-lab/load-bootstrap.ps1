# The Custom Script Extension runs this, passed in its command with
# -EncodedCommand. It opens the extension's protected settings, which only
# SYSTEM can decrypt, and runs bootstrap.ps1 from them, so the script is
# never a file on the VM that someone else could change first.
$ErrorActionPreference = 'Stop'
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
$script = $js.DeserializeObject([Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content))['conn3xBootstrap']
& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script))))
