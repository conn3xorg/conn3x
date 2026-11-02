$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
$utf=New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf
[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::InvariantCulture
$r=@{ok=$false}
$ended=$false
try{
$in=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((@($input)-join'').Trim()))|ConvertFrom-Json
$a=@{}
foreach($p in $in.args.PSObject.Properties){$a[$p.Name]=$p.Value}
$global:LASTEXITCODE=0
$o=& ([scriptblock]::Create($in.script)) $a
$r.rc=$global:LASTEXITCODE
if($in.text){$r.text=($o|Out-String);$l=$o|Select-Object -Last 1;if($l -is [bool]){$r.value=$l}}else{$r.value=$o}
$r.ok=$true
$ended=$true
}catch{$r.error=($_|Out-String);$ended=$true}
finally{
if(-not $ended){$r.error='the script called exit. Use return to finish, or throw to fail.'}
try{$j=$r|ConvertTo-Json -Depth 6 -Compress}catch{$j=@{ok=$false;error=($_|Out-String)}|ConvertTo-Json -Compress}
[Console]::Out.WriteLine('conn3x-result:'+[Convert]::ToBase64String($utf.GetBytes($j)))
}
