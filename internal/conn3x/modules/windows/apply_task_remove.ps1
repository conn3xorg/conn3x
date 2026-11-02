param($A)
$svc = New-Object -ComObject Schedule.Service
$svc.Connect()
try {
  # COM wants a folder without its trailing backslash, except the root.
  $path = ([string]$A.path).TrimEnd('\')
  $folder = $svc.GetFolder($(if ($path) { $path } else { '\' }))
  [void]$folder.GetTask([string]$A.name)
} catch { return }
$folder.DeleteTask([string]$A.name, 0)
