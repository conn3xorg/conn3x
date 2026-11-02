# expect: a read script may use Invoke only as Invoke('Members')
param($A)
([ADSI]'WinNT://./Guest,user').Invoke('SetPassword', 'x')
