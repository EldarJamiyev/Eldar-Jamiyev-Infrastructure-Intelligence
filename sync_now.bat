@echo off
cls
echo =======================================================
echo     EJII OPERATOR WORKSPACE — FORCING MANUAL SYNC      
echo =======================================================
echo.

:: Stage all changed and new source code files
echo [Step 1/3] Staging workspace alterations...
git add .

:: Commit files with a precise date and timestamp
echo [Step 2/3] Generating cryptographic commit checkpoint...
git commit -m "Manual sync verification: %date% %time%"

:: Force immediate upload upstream to GitHub main branch
echo [Step 3/3] Uploading architecture packets to GitHub remote...
echo.
git push origin main

echo.
echo =======================================================
echo     SUCCESS! Pipeline synchronized with GitHub.
echo =======================================================
echo.
pause
