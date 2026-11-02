param($A)
$s = Get-Service -Name $A.name -ErrorAction SilentlyContinue
if (-not $s) { return @{ exists = $false } }
$delayed = $false
$k = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $s.ServiceName) -ErrorAction SilentlyContinue
if ($k -and $k.DelayedAutostart -eq 1) { $delayed = $true }
@{ exists = $true; start = [string]$s.StartType; delayed = $delayed; status = [string]$s.Status }
