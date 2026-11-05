@echo off
powercfg /batteryreport /output "%TEMP%\ejii-battery-report.html"
echo Battery report saved to %TEMP%\ejii-battery-report.html
