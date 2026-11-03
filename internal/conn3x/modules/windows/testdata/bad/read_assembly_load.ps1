# expect: may load only Microsoft.Web.Administration
param($A)
$null = [Reflection.Assembly]::Load($A.name)
