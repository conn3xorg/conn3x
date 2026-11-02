param($A)
# LastBootUpTime moves by fractions of a second within one boot; BootId doesn't.
[string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters').BootId
