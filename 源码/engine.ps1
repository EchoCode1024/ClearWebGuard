param([ValidateSet('Apply','Remove','Check')][string]$Action, [string[]]$Domains, [string]$SourceExe)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'ClearWebGuard'
$install = Join-Path $env:ProgramFiles 'ClearWebGuard'
$stateFile = Join-Path $root 'baseline.json'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$begin = '# BEGIN CLEARWEBGUARD'
$end = '# END CLEARWEBGUARD'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ClearWebGuard'
function Secure-Folder($path) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Installation directory must not be a symbolic link.' }
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')) {
        $rights = if ($sid -eq 'S-1-5-32-545') { 'ReadAndExecute' } else { 'FullControl' }
        $rule = New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]::new($sid),$rights,'ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
function Read-Hosts { [IO.File]::ReadAllText($hosts) }
function Strip-Block([string]$content) {
    return [regex]::Replace($content,'(?ms)^# BEGIN CLEARWEBGUARD\r?\n.*?^# END CLEARWEBGUARD\r?\n?','')
}
function Write-Hosts([string]$content) { [IO.File]::WriteAllText($hosts,$content,[Text.Encoding]::UTF8) }
function Restore-State($state) {
    Write-Hosts (Strip-Block (Read-Hosts))
    foreach ($r in $state.Registry) {
        $current = Get-ItemProperty -LiteralPath $r.Path -Name $r.Name -ErrorAction SilentlyContinue
        if ($null -ne $current -and [string]$current.($r.Name) -eq [string]$r.Applied) {
            if ($r.Existed) { New-ItemProperty -LiteralPath $r.Path -Name $r.Name -Value $r.Value -PropertyType $r.Kind -Force | Out-Null }
            else { Remove-ItemProperty -LiteralPath $r.Path -Name $r.Name -ErrorAction SilentlyContinue }
        }
    }
    foreach ($d in $state.Dns) {
        $adapter = Get-NetAdapter | Where-Object { [string]$_.InterfaceGuid -eq $d.Guid }
        if (-not $adapter) { continue }
        foreach ($family in @(2,23)) {
            $now = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily $family
            $expected = if ($family -eq 2) { @('1.1.1.3','1.0.0.3') } else { @('2606:4700:4700::1113','2606:4700:4700::1003') }
            if (($now.ServerAddresses -join ',') -ne ($expected -join ',')) { continue }
            $saved = if ($family -eq 2) { $d.V4 } else { $d.V6 }
            if ($saved.Static -and @($saved.Addresses).Count -gt 0) { $now | Set-DnsClientServerAddress -ServerAddresses @($saved.Addresses) }
            else { $now | Set-DnsClientServerAddress -ResetServerAddresses }
        }
    }
    Clear-DnsClientCache
}
if ($Action -eq 'Check') {
    try {
        $test = Resolve-DnsName nudity.testcategory.com -Type A -DnsOnly -QuickTimeout
        if ('0.0.0.0' -in $test.IPAddress) { '通过：成人内容分类测试域名已被拦截。' }
        else { '注意：成人内容分类过滤未通过，请检查网络配置。' }
    } catch { '注意：分类测试查询失败，无法确认过滤状态。' }
    try {
        $test = Resolve-DnsName example.com -Type A -DnsOnly -QuickTimeout
        if (@($test | Where-Object { $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' }).Count -gt 0) { '通过：普通域名解析正常。' }
        else { '注意：普通域名解析异常。' }
    } catch { '注意：普通域名解析失败。' }
    foreach ($d in $Domains) {
        try { $test=Resolve-DnsName $d -Type A -QuickTimeout; if ('0.0.0.0' -in $test.IPAddress) { "已拦截：$d" } else { "需检查：$d 未返回阻断地址。" } }
        catch { "需检查：$d 查询失败，不能视为已确认拦截。" }
    }
    foreach ($browser in @('Google\Chrome','Microsoft\Edge')) {
        $key='HKLM:\SOFTWARE\Policies\'+$browser
        $mode=(Get-ItemProperty -Path $key -Name DnsOverHttpsMode -ErrorAction SilentlyContinue).DnsOverHttpsMode
        $list=Get-ItemProperty -Path ($key+'\URLBlocklist') -ErrorAction SilentlyContinue
        $missing=@($Domains | Where-Object { $_ -notin @($list.PSObject.Properties.Value) })
        if ($mode -eq 'off' -and $missing.Count -eq 0) { "策略已写入：$browser（浏览器实际加载状态需重启后核对）。" }
        else { "策略需检查：$browser" }
    }
    exit 0
}
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission required.' }
if ($Action -eq 'Remove') {
    if (-not (Test-Path $stateFile)) { throw 'No baseline available; refusing to guess previous settings.' }
    Restore-State (Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json)
    Remove-Item -LiteralPath $uninstallKey -Recurse -Force -ErrorAction SilentlyContinue
    $shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'ClearWebGuard.lnk'
    Remove-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $root 'domains.txt') -Force -ErrorAction SilentlyContinue
    Move-Item -LiteralPath $stateFile -Destination (Join-Path $root ('baseline-removed-' + (Get-Date -Format 'yyyyMMddHHmmssfff') + '.json'))
    # Keep an archived baseline for administrator troubleshooting. No self-reinstall or hidden persistence.
    'Settings restored. Earlier restrictions outside this application are preserved.'
    exit 0
}
foreach ($d in $Domains) {
    if ($d.Length -gt 253 -or $d -notmatch '^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { throw "Invalid domain: $d" }
}
foreach ($server in @('1.1.1.3','1.0.0.3')) {
    $test = Resolve-DnsName nudity.testcategory.com -Server $server -Type A -DnsOnly -QuickTimeout
    if ('0.0.0.0' -notin $test.IPAddress) { throw "Family DNS unavailable: $server. No settings were changed." }
}
Secure-Folder $root
Secure-Folder $install
$first = -not (Test-Path $stateFile)
$originalState = if ($first) { $null } else { [IO.File]::ReadAllText($stateFile) }
if ($first) { $state = [pscustomobject]@{ Registry = @(); Dns = @() } }
else { $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json }
$priorHosts = Read-Hosts
$priorDns = @(Get-NetAdapter -Physical | ForEach-Object {
    $a = $_
    $record = [ordered]@{ Guid = [string]$a.InterfaceGuid; V4 = $null; V6 = $null }
    foreach ($f in @(2,23)) {
        $v = if ($f -eq 2) { 'V4' } else { 'V6' }
        $protocol = if ($f -eq 2) { 'Tcpip' } else { 'Tcpip6' }
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $protocol + '\Parameters\Interfaces\{' + $a.InterfaceGuid + '}'
        $nameServer = (Get-ItemProperty -LiteralPath $path -Name NameServer -ErrorAction SilentlyContinue).NameServer
        $record[$v] = @{ Static = (-not [string]::IsNullOrWhiteSpace($nameServer)); Addresses = @((Get-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily $f).ServerAddresses) }
    }
    [pscustomobject]$record
})
foreach ($record in $priorDns) { if ($record.Guid -notin @($state.Dns | ForEach-Object { $_.Guid })) { $state.Dns += $record } }
$changes = @()
foreach ($browser in @('Google\Chrome','Microsoft\Edge')) {
    $key = 'HKLM:\SOFTWARE\Policies\' + $browser
    $changes += [pscustomobject]@{ Path=$key; Name='DnsOverHttpsMode'; Applied='off' }
    $index = 1
    foreach ($domain in $Domains) {
        # Dedicated names avoid overwriting browser policy entries created by other administrators.
        $changes += [pscustomobject]@{ Path=($key+'\URLBlocklist'); Name=([string](800+$index)); Applied=$domain }
        $index++
    }
}
$transaction = [pscustomobject]@{ Registry=@(); Dns=$priorDns }
foreach ($c in $changes) {
    $item = Get-Item -LiteralPath $c.Path -ErrorAction SilentlyContinue
    $exists = $null -ne $item -and $c.Name -in $item.GetValueNames()
    $r = [pscustomobject]@{ Path=$c.Path; Name=$c.Name; Applied=$c.Applied; Existed=$exists; Value=$null; Kind='String' }
    if ($exists) { $r.Value=$item.GetValue($c.Name); $r.Kind=[string]$item.GetValueKind($c.Name) }
    $transaction.Registry += $r
    $old = @($state.Registry | Where-Object { $_.Path -eq $c.Path -and $_.Name -eq $c.Name })
    if ($old.Count -eq 0) { $state.Registry += $r }
    else { $old[0].Applied = $c.Applied }
}
try {
    $state | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $stateFile -Encoding UTF8
    $block = @($begin)
    foreach ($domain in $Domains) { foreach ($name in @($domain,('www.'+$domain))) { $block += "0.0.0.0 $name"; $block += ":: $name" } }
    $block += $end
    Write-Hosts ((Strip-Block $priorHosts).TrimEnd() + "`r`n" + ($block -join "`r`n") + "`r`n")
    foreach ($c in $changes) {
        New-Item -Path $c.Path -Force | Out-Null
        New-ItemProperty -LiteralPath $c.Path -Name $c.Name -Value $c.Applied -PropertyType String -Force | Out-Null
    }
    foreach ($adapter in Get-NetAdapter -Physical) { Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses @('1.1.1.3','1.0.0.3','2606:4700:4700::1113','2606:4700:4700::1003') }
    $target = Join-Path $install 'ClearWebGuard.exe'
    if ([IO.Path]::GetFullPath($SourceExe) -ne [IO.Path]::GetFullPath($target)) { Copy-Item -LiteralPath $SourceExe -Destination $target -Force }
    $Domains | Set-Content -LiteralPath (Join-Path $root 'domains.txt') -Encoding UTF8
    New-Item -Path $uninstallKey -Force | Out-Null
    foreach ($pair in @(@('DisplayName','清朗防护 ClearWebGuard'),@('DisplayVersion','1.0.0'),@('Publisher','Local build'),@('InstallLocation',$install),@('UninstallString',('"'+$target+'" --uninstall')))) { New-ItemProperty -LiteralPath $uninstallKey -Name $pair[0] -Value $pair[1] -PropertyType String -Force | Out-Null }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'ClearWebGuard.lnk'))
    $shortcut.TargetPath = $target
    $shortcut.Save()
    Clear-DnsClientCache
    'Protection installed. Restart browsers to reload policies.'
} catch {
    $failure = $_
    try {
        Restore-State $transaction; Write-Hosts $priorHosts
        if ($first) { Remove-Item -LiteralPath $stateFile -Force }
        else { [IO.File]::WriteAllText($stateFile,$originalState,[Text.Encoding]::UTF8) }
    } catch { throw "Apply failed: $failure. Rollback also failed: $_. Keep baseline.json for administrator recovery." }
    throw "Apply failed; system settings rolled back: $failure"
}
