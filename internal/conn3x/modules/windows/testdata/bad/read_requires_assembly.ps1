#Requires -Assemblies System.Windows.Forms
# expect: may not load an assembly with #Requires -Assemblies
param($A)
$A.name
