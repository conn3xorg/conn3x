# expect: must be opened read-only
param($A)
$sm = [Microsoft.Web.Administration.ServerManager]::new()
$sm.ApplicationPools[$A.name]
