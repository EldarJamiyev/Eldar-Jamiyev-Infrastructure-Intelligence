# EJI Network Diagnostics: Dynamic Default Gateway Port Connectivity
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if (-not $gw) {
    $gw = (Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.DefaultIPGateway }).DefaultIPGateway[0]
}
if (-not $gw) {
    $gw = '192.168.31.1'
}

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  EJI Gateway Port Connectivity Test" -ForegroundColor Cyan
Write-Host "  Target Gateway IP: $gw | Target Port: 80 (HTTP / Admin Interface)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

Test-NetConnection -ComputerName $gw -Port 80
