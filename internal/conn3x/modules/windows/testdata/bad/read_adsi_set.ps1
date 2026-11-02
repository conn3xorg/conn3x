# expect: a read script may use InvokeMember only to get objectSid
param($A)
$u = [ADSI]'WinNT://./Guest,user'
$u.GetType().InvokeMember('Description', 'SetProperty', $null, $u, @('x'))
