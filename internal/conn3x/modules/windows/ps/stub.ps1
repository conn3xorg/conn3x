$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
$utf=New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding=$utf
[Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::InvariantCulture
$r=@{ok=$false}
$ended=$false
try{
Add-Type -AssemblyName System.Web.Extensions
$js=New-Object Web.Script.Serialization.JavaScriptSerializer
$js.MaxJsonLength=[int]::MaxValue
$in=$js.DeserializeObject([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((@($input)-join'').Trim())))
$a=@{}
foreach($k in $in['args'].Keys){$a[$k]=$in['args'][$k]}
$global:LASTEXITCODE=0
$o=& ([scriptblock]::Create($in['script'])) $a
$r.rc=$global:LASTEXITCODE
if($in['text']){$r.text=($o|Out-String -Width 65536)-replace'(?m)[ \t]+(?=\r?$)','';$l=$o|Select-Object -Last 1;if($l -is [bool]){$r.value=$l}}else{$r.value=$o}
$r.ok=$true
$ended=$true
}catch{$r.error=$_.Exception.Message+" (line $($_.InvocationInfo.ScriptLineNumber))";$ended=$true}
finally{
if(-not $ended){$r.error='the script called exit. Use return to finish, or throw to fail.'}
try{$j=$r|ConvertTo-Json -Depth 6 -Compress}catch{$j=@{ok=$false;error=$_.Exception.Message}|ConvertTo-Json -Compress}
[Console]::Out.WriteLine('conn3x-result:'+[Convert]::ToBase64String($utf.GetBytes($j)))
}
