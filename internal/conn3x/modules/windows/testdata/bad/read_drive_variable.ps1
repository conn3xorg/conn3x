# expect: the C: drive through a variable
param($A)
${C:\out.txt} = $A.a
