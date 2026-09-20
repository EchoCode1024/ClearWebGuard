$ErrorActionPreference='Stop'
# Isolated integration harness: no real adapter, system hosts file or machine policies are modified.
$testRoot=Join-Path $env:TEMP ('ClearWebGuardTest-'+[guid]::NewGuid().ToString('N'))
$regRoot='HKCU:\Software\ClearWebGuardTest-'+[guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $testRoot | Out-Null
$fakeHosts=Join-Path $testRoot 'hosts'
[IO.File]::WriteAllText($fakeHosts,"127.0.0.1 localhost`r`n# prior rule`r`n")
$fakeSource=Join-Path $testRoot 'source.exe'
[IO.File]::WriteAllText($fakeSource,'test executable placeholder')
$engine=Get-Content (Join-Path $PSScriptRoot 'engine.ps1') -Raw
$engine=$engine.Replace("Join-Path `$env:ProgramData 'ClearWebGuard'", "'"+$testRoot+"\data'")
$engine=$engine.Replace("Join-Path `$env:ProgramFiles 'ClearWebGuard'", "'"+$testRoot+"\install'")
$engine=$engine.Replace("Join-Path `$env:SystemRoot 'System32\drivers\etc\hosts'", "'"+$fakeHosts+"'")
$engine=$engine.Replace("([Environment]::GetFolderPath('CommonPrograms'))", "('"+$testRoot+"')")
$engine=$engine.Replace('HKLM:', $regRoot)
$engine=[regex]::Replace($engine,'(?m)^if \(-not \(\[Security.Principal.WindowsPrincipal\].*?Administrator permission required.*?\r?\n','')
$engine=[regex]::Replace($engine,'(?s)function Secure-Folder\(\$path\) \{.*?\r?\n\}\r?\nfunction Read-Hosts', 'function Secure-Folder($path) { New-Item -ItemType Directory -Path $path -Force | Out-Null }'+"`r`nfunction Read-Hosts")
$engine=$engine.Replace('$shell = New-Object -ComObject WScript.Shell','$shell = New-FakeShell')
$testEngine=Join-Path $testRoot 'engine.ps1'
[IO.File]::WriteAllText($testEngine,$engine,[Text.Encoding]::UTF8)
$global:fakeDns=@{2=@('192.0.2.53');23=@()}
$global:failDns=$false
function global:Get-NetAdapter { param([switch]$Physical) [pscustomobject]@{InterfaceIndex=987;InterfaceGuid='12345678-1234-1234-1234-123456789abc'} }
function global:Get-DnsClientServerAddress { param($InterfaceIndex,$AddressFamily) [pscustomobject]@{InterfaceIndex=987;AddressFamily=$AddressFamily;ServerAddresses=@($global:fakeDns[[int]$AddressFamily])} }
function global:Set-DnsClientServerAddress {
    param([Parameter(ValueFromPipeline=$true)]$InputObject,$InterfaceIndex,[string[]]$ServerAddresses,[switch]$ResetServerAddresses)
    process {
        if($global:failDns){$global:failDns=$false;throw 'Injected DNS write failure'}
        if($InputObject){
            $f=[int]$InputObject.AddressFamily
            if($ResetServerAddresses){$global:fakeDns[$f]=if($f -eq 2){@('192.0.2.53')}else{@()}}
            else{$global:fakeDns[$f]=@($ServerAddresses)}
        }else{$global:fakeDns[2]=@($ServerAddresses|Where-Object{$_ -notmatch ':'});$global:fakeDns[23]=@($ServerAddresses|Where-Object{$_ -match ':'})}
    }
}
function global:Resolve-DnsName {param($Server,$Type,[switch]$DnsOnly,[switch]$QuickTimeout,[Parameter(Position=0)]$Name) [pscustomobject]@{IPAddress='0.0.0.0'} }
function global:Clear-DnsClientCache {}
function global:New-FakeShell {
    $obj=New-Object psobject
    $obj|Add-Member ScriptMethod CreateShortcut {param($path) $link=[pscustomobject]@{TargetPath=''}; $link|Add-Member ScriptMethod Save {};return $link}
    return $obj
}
function Assert($condition,$message){if(-not $condition){throw "ASSERT FAILED: $message"};Write-Output "PASS: $message"}
try {
    $chrome=$regRoot+'\SOFTWARE\Policies\Google\Chrome'
    New-Item -Path $chrome -Force|Out-Null
    New-ItemProperty -Path $chrome -Name DnsOverHttpsMode -Value 'secure' -PropertyType String|Out-Null
    & $testEngine -Action Apply -Domains @('missav.ws','123av.com') -SourceExe $fakeSource
    Assert ((Get-Content $fakeHosts -Raw).Contains('# BEGIN CLEARWEBGUARD')) 'installs owned hosts block'
    Assert (($global:fakeDns[2] -join ',') -eq '1.1.1.3,1.0.0.3') 'configures IPv4 filter'
    Assert ((Get-ItemProperty $chrome).DnsOverHttpsMode -eq 'off') 'installs browser policy'
    $baselineBefore=Get-Content (Join-Path $testRoot 'data\baseline.json') -Raw
    $hostsBefore=Get-Content $fakeHosts -Raw
    $global:failDns=$true
    $failed=$false
    try{& $testEngine -Action Apply -Domains @('missav.ws','123av.com','example.org') -SourceExe $fakeSource}catch{$failed=$true}
    Assert $failed 'reports injected configuration failure'
    Assert ((Get-Content $fakeHosts -Raw) -eq $hostsBefore) 'rolls back hosts after failure'
    Assert ((Get-Content (Join-Path $testRoot 'data\baseline.json') -Raw) -eq $baselineBefore) 'preserves original recovery baseline after failure'
    & $testEngine -Action Apply -Domains @('missav.ws','123av.com','example.org') -SourceExe $fakeSource
    $content=Get-Content $fakeHosts -Raw
    Assert (([regex]::Matches($content,'# BEGIN CLEARWEBGUARD')).Count -eq 1) 'repeated apply does not duplicate block'
    Assert ($content.Contains('0.0.0.0 example.org')) 'adds custom domain'
    [IO.File]::AppendAllText($fakeHosts,"# added by another administrator`r`n")
    & $testEngine -Action Remove -Domains @('missav.ws','123av.com') -SourceExe $fakeSource
    $content=Get-Content $fakeHosts -Raw
    Assert (-not $content.Contains('# BEGIN CLEARWEBGUARD')) 'removes only owned block'
    Assert ($content.Contains('# prior rule') -and $content.Contains('# added by another administrator')) 'preserves preexisting and later hosts entries'
    Assert ((Get-ItemProperty $chrome).DnsOverHttpsMode -eq 'secure') 'restores prior policy value'
    Assert (($global:fakeDns[2] -join ',') -eq '192.0.2.53') 'restores automatic DNS mode'
    Assert (-not(Test-Path (Join-Path $testRoot 'data\baseline.json'))) 'archives baseline after uninstall for clean reinstall'
    'ALL ISOLATED INTEGRATION TESTS PASSED'
}finally{
    # Only remove this run's explicitly generated registry key. Keep temporary files for inspection.
    if($regRoot -match '^HKCU:\\Software\\ClearWebGuardTest-[a-f0-9]{32}$'){Remove-Item -LiteralPath $regRoot -Recurse -Force -ErrorAction SilentlyContinue}
}
