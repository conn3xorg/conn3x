# expect: only with -WhatIf
param($A)
Install-WindowsFeature -Name $A.a
