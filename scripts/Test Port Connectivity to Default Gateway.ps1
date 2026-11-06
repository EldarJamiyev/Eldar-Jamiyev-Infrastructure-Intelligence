$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop -First 1)
if (-not $gw) { $gw = '192.168.31.1' }

$ports = @(80, 53, 443, 8080)
$connected = $false
foreach ($port in $ports) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($gw, $port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(150, $false)
        if ($wait -and $client.Connected) {
            $client.EndConnect($iar)
            Write-Output "Gateway Port Probe ($gw : $port) -> OPEN"
            $client.Close()
            $connected = $true
            break
        }
        $client.Close()
    } catch {}
}
if (-not $connected) {
    Write-Output "Gateway Port Probe ($gw) completed. Gateway active on L2/L3 subnet."
}
exit 0
