$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$inputReader = [IO.StreamReader]::new([Console]::OpenStandardInput())
$cfg = $inputReader.ReadLine() | ConvertFrom-Json
$child = $null
$saved = $null
function Get-UplinkSignature {
    $items = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') -and $_.InterfaceAlias -notlike 'tunnelX-*' } | ForEach-Object {
        $r = $_
        $nic = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -IncludeHidden -ErrorAction SilentlyContinue
        # Ignore RFC 4941 temporary IPv6 addresses and link-local addresses so periodic
        # privacy-address rotation does not trigger false-positive TUN reconnect loops.
        $ips = @(Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue | Where-Object {
            $_.AddressState -eq 'Preferred' -and $_.SuffixOrigin -ne 'Random' -and $_.IPAddress -notlike 'fe80:*'
        } | Select-Object -ExpandProperty IPAddress | Sort-Object)
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $r.DestinationPrefix,$r.InterfaceIndex,$r.NextHop,$r.RouteMetric,$nic.Status,($ips -join ',')
    } | Sort-Object)
    return ($items -join ';')
}
function Get-UplinkInfo {
    $ifV4 = 0
    $ifV6 = 0
    $dns = @()
    $r4 = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike 'tunnelX-*' } | ForEach-Object {
        $iface = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        [PSCustomObject]@{ Route = $_; Cost = $_.RouteMetric + $(if ($iface) { $iface.InterfaceMetric } else { 0 }) }
    } | Sort-Object Cost | Select-Object -First 1)
    if ($r4.Count -gt 0) { $ifV4 = [int]$r4[0].Route.InterfaceIndex }
    $r6 = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike 'tunnelX-*' } | ForEach-Object {
        $iface = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
        [PSCustomObject]@{ Route = $_; Cost = $_.RouteMetric + $(if ($iface) { $iface.InterfaceMetric } else { 0 }) }
    } | Sort-Object Cost | Select-Object -First 1)
    if ($r6.Count -gt 0) { $ifV6 = [int]$r6[0].Route.InterfaceIndex }
    foreach ($idx in (@($ifV4, $ifV6) | Where-Object { $_ -gt 0 } | Select-Object -Unique)) {
        $addrs = @(Get-DnsClientServerAddress -InterfaceIndex $idx -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses)
        foreach ($a in $addrs) {
            if ($a -and $a -notlike '127.*' -and $a -ne '::1' -and $a -notlike '198.18.*' -and $a -notlike 'fec0:*') {
                if ($dns -notcontains $a) { $dns += $a }
            }
        }
    }
    return @{ if_v4 = $ifV4; if_v6 = $ifV6; dns = @($dns) }
}
function Save-State {
    $tmp = $cfg.State + '.new'
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($cfg.State)) | Out-Null
    [IO.File]::WriteAllText($tmp, ($script:saved | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $cfg.State -Force
}
function Restore-State {
    if (-not (Test-Path -LiteralPath $cfg.State)) { return }
    $old = Get-Content -LiteralPath $cfg.State -Raw | ConvertFrom-Json
    if ($old.Alias -notmatch '^tunnelX-[a-f0-9]{12}$' -or $old.GUID -notmatch '^\{[a-fA-F0-9-]{36}\}$') { throw 'TUN 恢复记录无效' }
    # Remove only our marked DNS policy first so DNS recovers immediately. Never clear another VPN's NRPT table.
    $dnsRules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -eq $old.Alias -and $_.DisplayName -eq $old.Alias })
    if ($dnsRules.Count -gt 0) {
        $dnsRules | Remove-DnsClientNrptRule -Force -ErrorAction Stop
    }
    foreach ($r in $old.Routes) {
        $ip = $null
        if (-not [Net.IPAddress]::TryParse(($r.Prefix -split '/')[0],[ref]$ip) -or $r.Metric -ne 4276 -or $r.Prefix -notmatch '/(32|128)$') { throw 'TUN 路由恢复记录无效' }
        Get-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq $r.NextHop -and $_.RouteMetric -eq 4276 } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
    $adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceGuid.ToString().Trim('{}') -eq $old.GUID.Trim('{}') -and $_.Name -eq $old.Alias }
    if ($adapter) {
        Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') -and $_.RouteMetric -eq 1 } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -in @('198.18.77.1','fd01:198:18::1') -and $_.PrefixOrigin -eq 'Manual' } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
    }
    if ($old.ChildPID -and $old.ChildStart) {
        $p = Get-Process -Id $old.ChildPID -ErrorAction SilentlyContinue
        $expected = [IO.Path]::GetFullPath((Join-Path $cfg.Runtime 'tun2socks.exe'))
        if ($p -and $p.Path -eq $expected -and $p.StartTime.ToUniversalTime().Ticks.ToString() -eq $old.ChildStart) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    if ($dnsRules.Count -gt 0) { Clear-DnsClientCache }
    Remove-Item -LiteralPath $cfg.State -Force
}
try {
    if ($cfg.Restore) { Restore-State; [Console]::Out.WriteLine('TUN_RESTORED'); exit 0 }
    if (Test-Path -LiteralPath $cfg.State) { throw '存在未恢复的 TUN 状态，请先恢复网络' }
    $alias = 'tunnelX-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
    $guid = '{' + [Guid]::NewGuid().ToString() + '}'
    $saved = @{Alias=$alias;GUID=$guid;Routes=@();ChildPID=0;ChildStart=''}
    $networkBaseline = Get-UplinkSignature
    $uplinkInfo = Get-UplinkInfo
    # Resolve original egress before installing any capture route.
    $exits = @()
    foreach ($address in $cfg.Exempt | Select-Object -Unique) {
        $route = @(Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' -and $null -ne $_.NextHop })[0]
        if (-not $route -and $address -ne $cfg.Exempt[0]) { continue }
        if (-not $route -or $route.InterfaceAlias -like 'tunnelX-*') { throw '无法确定原有节点出口路由' }
        $bits = if ($address.Contains(':')) {128} else {32}
        $prefix = $address + '/' + $bits
        if (-not (Get-NetRoute -DestinationPrefix $prefix -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue)) {
            $exits += @{Prefix=$prefix;Index=$route.InterfaceIndex;NextHop=$route.NextHop;Metric=4276}
        }
    }
    Save-State
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $cfg.Runtime 'tun2socks.exe'
    $start.WorkingDirectory = $cfg.Runtime
    $start.Arguments = '--device tun://' + $alias + '?guid=' + $guid + ' --proxy socks5://' + $cfg.SOCKS + ' --mtu 1400 --loglevel error --tcp-auto-tuning'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $child = [Diagnostics.Process]::Start($start)
    $saved.ChildPID = $child.Id
    $saved.ChildStart = $child.StartTime.ToUniversalTime().Ticks.ToString()
    Save-State
    $adapter = $null
    for ($i=0; $i -lt 70; $i++) {
        if ($child.HasExited) { throw 'TUN 网络栈未能启动，请检查组件或管理员权限' }
        $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
        if ($adapter) { break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $adapter -or $adapter.InterfaceGuid.ToString().Trim('{}') -ne $guid.Trim('{}')) { throw 'TUN 虚拟网卡未就绪' }
    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1 -NlMtuBytes 1400 -DadTransmits 0
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress '198.18.77.1' -PrefixLength 30 -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null
    $ipv6Enabled = $false
    try {
        Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -AutomaticMetric Disabled -InterfaceMetric 1 -NlMtuBytes 1400 -DadTransmits 0 -ErrorAction Stop
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress 'fd01:198:18::1' -PrefixLength 126 -AddressFamily IPv6 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $ipv6Enabled = $true
    } catch {
        # IPv6 may be disabled on the host; continue cleanly in IPv4-only mode.
        $ipv6Enabled = $false
    }
    $preferred = $false
    for ($i=0; $i -lt 30; $i++) {
        $v4Ready = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq '198.18.77.1' -and $_.AddressState -eq 'Preferred' })
        if ($v4Ready.Count -ge 1) {
            if (-not $ipv6Enabled) { $preferred = $true; break }
            $v6Ready = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq 'fd01:198:18::1' -and $_.AddressState -eq 'Preferred' })
            if ($v6Ready.Count -ge 1) { $preferred = $true; break }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $preferred) {
        # If IPv4 is preferred but IPv6 failed to become preferred, proceed with IPv4 only.
        $v4Ready = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq '198.18.77.1' -and $_.AddressState -eq 'Preferred' })
        if ($v4Ready.Count -ge 1) { $ipv6Enabled = $false; $preferred = $true }
    }
    if (-not $preferred) { throw 'TUN 虚拟网卡地址未就绪' }
    foreach ($r in $exits) {
        $saved.Routes += $r
        Save-State
        New-NetRoute -DestinationPrefix $r.Prefix -InterfaceIndex $r.Index -NextHop $r.NextHop -RouteMetric 4276 -PolicyStore ActiveStore | Out-Null
    }
    foreach ($prefix in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {
        if ($prefix.Contains(':') -and -not $ipv6Enabled) { continue }
        $hop = if ($prefix.Contains(':')) {'::'} else {'0.0.0.0'}
        New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $adapter.ifIndex -NextHop $hop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @('1.1.1.1','8.8.8.8')
    Add-DnsClientNrptRule -Namespace '.' -NameServers @('1.1.1.1','8.8.8.8') -DisplayName $alias -Comment $alias | Out-Null
    Clear-DnsClientCache
    [Console]::Out.WriteLine('TUN_UPLINK:' + ($uplinkInfo | ConvertTo-Json -Compress))
    [Console]::Out.WriteLine('TUN_READY')
    [Console]::Out.Flush()
    # EOF means the owning desktop process disconnected or exited unexpectedly.
    $read = $inputReader.ReadLineAsync()
    $lastPoll = [DateTime]::UtcNow
    $lastTick = $lastPoll
    $changedCount = 0
    while (-not $read.Wait(250)) {
        if ($child.HasExited) { throw 'TUN 网络栈意外退出' }
        $now = [DateTime]::UtcNow
        if (($now - $lastTick).TotalSeconds -gt 25) {
            [Console]::Out.WriteLine('TUN_NETWORK_CHANGED:resume'); [Console]::Out.Flush(); break
        }
        $lastTick = $now
        if (($now - $lastPoll).TotalSeconds -ge 3) {
            $lastPoll = $now
            try {
                $signature = Get-UplinkSignature
                if ($signature -ne $networkBaseline) { $changedCount++ } else { $changedCount = 0 }
                if ($changedCount -ge 2) {
                    [Console]::Out.WriteLine('TUN_NETWORK_CHANGED:route'); [Console]::Out.Flush(); break
                }
            } catch { } # A transient WMI error must not tear down a working tunnel.
        }
    }
} catch {
    [Console]::Out.WriteLine('TUN_ERROR:' + $_.Exception.Message)
} finally {
    if (-not $cfg.Restore) {
        try { Restore-State } catch { [Console]::Out.WriteLine('TUN_ERROR:TUN 网络恢复未完成，请以管理员权限恢复网络') }
        if ($child -and -not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
    }
}
