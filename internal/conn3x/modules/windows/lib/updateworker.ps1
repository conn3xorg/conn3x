param([string]$In, [string]$Out)
# Runs as SYSTEM from a one-off scheduled task: Windows Update refuses to
# download or install for a remote login. Its values come in a file, and its
# result goes out in one, written whole.
$ErrorActionPreference = 'Stop'
try {
  $A = [IO.File]::ReadAllText($In) | ConvertFrom-Json
  $session = New-Object -ComObject Microsoft.Update.Session
  $session.ClientApplicationID = 'Conn3x'
  $installed = @(); $failed = @(); $reboot = $false
  # Some updates only appear once others are in, such as Defender's platform
  # after its definitions, so search again until nothing new is left.
  for ($round = 0; $round -lt 3 -and -not $reboot; $round++) {
    $found = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
    $want = New-Object -ComObject Microsoft.Update.UpdateColl
    $names = @()
    foreach ($u in $found) {
      $kbs = @($u.KBArticleIDs | ForEach-Object { 'KB' + $_ })
      $cats = @($u.Categories | ForEach-Object { [string]$_.CategoryID })
      if (-not ($cats | Where-Object { $A.categories -contains $_ })) { continue }
      if (@($A.accept).Count -and -not ($kbs | Where-Object { $A.accept -contains $_ })) { continue }
      if ($kbs | Where-Object { $A.reject -contains $_ }) { continue }
      $name = ((($kbs -join ',') + ' ' + $u.Title).Trim())
      if ($failed | Where-Object { $_.StartsWith($name) }) { continue }
      if (-not $u.EulaAccepted) { $u.AcceptEula() }
      [void]$want.Add($u)
      $names += $name
    }
    if ($want.Count -eq 0) { break }
    $d = $session.CreateUpdateDownloader()
    $d.Updates = $want
    [void]$d.Download()
    $i = $session.CreateUpdateInstaller()
    $i.Updates = $want
    $res = $i.Install()
    for ($n = 0; $n -lt $want.Count; $n++) {
      # 2 succeeded, 3 succeeded with errors; 4 failed, 5 aborted.
      $code = $res.GetUpdateResult($n).ResultCode
      if ($code -eq 2 -or $code -eq 3) { $installed += $names[$n] } else { $failed += ($names[$n] + ' (result ' + $code + ')') }
    }
    $reboot = [bool]$res.RebootRequired
  }
  $r = @{ ok = $true; installed = $installed; failed = $failed; reboot = $reboot }
} catch {
  $r = @{ ok = $false; error = $_.Exception.Message }
}
[IO.File]::WriteAllText($Out + '.part', ($r | ConvertTo-Json -Depth 4 -Compress))
[IO.File]::Move($Out + '.part', $Out)
