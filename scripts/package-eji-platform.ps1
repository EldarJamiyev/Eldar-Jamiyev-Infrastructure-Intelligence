# EJI Platform Master Delivery Packaging Script
# Assembles clean, verified production deployment bundle

$ErrorActionPreference = "Stop"

$workspace = "C:\Users\eldar\OneDrive\Documenti\Eldar Jamiyev Infrastructure Intelligence"
Set-Location $workspace

$targetDir = Join-Path $workspace "EJI-Platform"
$targetZip = Join-Path $workspace "EJI-Platform.zip"

Write-Host "===> Cleaning prior packaging artifacts..."
if (Test-Path $targetDir) { Remove-Item -Recurse -Force $targetDir }
if (Test-Path $targetZip) { Remove-Item -Force $targetZip }

Write-Host "===> Assembling EJI-Platform delivery folder..."
New-Item -ItemType Directory -Path $targetDir | Out-Null

$itemsToCopy = @(
    "src",
    "public",
    "data",
    "tests",
    "desktop",
    "mobile",
    "bin",
    "docs",
    "policies",
    "runbooks",
    "scripts",
    "package.json",
    "package-lock.json",
    "README.md",
    "EJI_IMPLEMENTATION_CHECKPOINT.md"
)

foreach ($item in $itemsToCopy) {
    $srcPath = Join-Path $workspace $item
    if (Test-Path $srcPath) {
        Write-Host "  -> Copying $item..."
        if ((Get-Item $srcPath) -is [System.IO.DirectoryInfo]) {
            # Copy directory excluding node_modules, .git, *.bak
            Copy-Item -Path $srcPath -Destination $targetDir -Recurse -Exclude @("*.bak", "*.log", "node_modules", ".git")
        } else {
            Copy-Item -Path $srcPath -Destination $targetDir
        }
    } else {
        Write-Host "  -- Note: $item does not exist, skipping."
    }
}

Write-Host "===> Packaging into EJI-Platform.zip..."
Compress-Archive -Path (Join-Path $targetDir "*") -DestinationPath $targetZip -CompressionLevel Optimal

$zipItem = Get-Item $targetZip
$sizeMb = [math]::Round($zipItem.Length / 1MB, 2)

Write-Host "========================================================================"
Write-Host "  EJI-Platform.zip CREATED SUCCESSFULLY!"
Write-Host "  Path: $targetZip"
Write-Host "  Archive Size: $sizeMb MB"
Write-Host "========================================================================"
