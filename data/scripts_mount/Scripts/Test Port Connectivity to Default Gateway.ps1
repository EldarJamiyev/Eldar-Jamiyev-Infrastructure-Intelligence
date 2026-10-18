$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
if (-not $gw) { $gw = '192.168.31.1' }
Test-NetConnection -ComputerName $gw -Port 53 -InformationLevel Detailed
