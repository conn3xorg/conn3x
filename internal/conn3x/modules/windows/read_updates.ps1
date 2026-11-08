param($A)
# What Windows Update would install for these categories and lists. Searching
# works from an SSH login; downloading and installing don't (apply_updates.ps1).
$session = New-Object -ComObject Microsoft.Update.Session
$found = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
$out = @()
foreach ($u in $found) {
  $kbs = @($u.KBArticleIDs | ForEach-Object { 'KB' + $_ })
  $cats = @($u.Categories | ForEach-Object { [string]$_.CategoryID })
  if (-not ($cats | Where-Object { $A.categories -contains $_ })) { continue }
  if (@($A.accept).Count -and -not ($kbs | Where-Object { $A.accept -contains $_ })) { continue }
  if ($kbs | Where-Object { $A.reject -contains $_ }) { continue }
  $name = $kbs -join ','
  if ($name) { $name += ' ' }
  $out += $name + $u.Title
}
@{ pending = $out }
