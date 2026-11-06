Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 ProcessName, Id, CPU
