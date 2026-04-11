# FIFA 17 FUT Server - Automated Test Script
# Run this from the repo root on your Windows PC
# Usage: .\test.ps1

$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\test-results.log"

Write-Host "=== FIFA 17 FUT Server Test ===" -ForegroundColor Cyan

# Step 1: Pull latest changes
Write-Host "`n[1/6] Pulling latest changes..." -ForegroundColor Yellow
git pull 2>&1 | Tee-Object -Variable gitOutput
Add-Content $resultsFile "--- GIT PULL ---`n$gitOutput`n"

# Step 2: Kill FIFA 17 if running
Write-Host "`n[2/6] Stopping FIFA 17..." -ForegroundColor Yellow
Stop-Process -Name FIFA17 -Force -ErrorAction SilentlyContinue
Start-Sleep 2

# Step 3: Build DLL
Write-Host "`n[3/6] Building DLL..." -ForegroundColor Yellow
$env:Path += ";$env:USERPROFILE\.cargo\bin"

# Find vcvars
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}

if ($vcvars -ne "") {
    $buildOutput = cmd /c "`"$vcvars`" && cd /d `"$repoRoot\dll-proxy`" && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib 2>&1"
    Write-Host $buildOutput
    Add-Content $resultsFile "--- BUILD ---`n$buildOutput`n"
} else {
    Write-Host "ERROR: Visual Studio Build Tools not found!" -ForegroundColor Red
    Add-Content $resultsFile "--- BUILD ---`nERROR: vcvars not found`n"
}

# Step 4: Deploy DLL and clean log
Write-Host "`n[4/6] Deploying..." -ForegroundColor Yellow
Remove-Item $logFile -Force -ErrorAction SilentlyContinue
if (Test-Path "$repoRoot\dll-proxy\dinput8.dll") {
    Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
    Write-Host "DLL copied to game directory"
} else {
    Write-Host "ERROR: dinput8.dll not found after build!" -ForegroundColor Red
}

# Step 5: Start server and launch game
Write-Host "`n[5/6] Starting server..." -ForegroundColor Yellow
$serverJob = Start-Job -ScriptBlock {
    param($repoRoot)
    Set-Location $repoRoot
    node "$repoRoot\server-standalone\server.mjs" 2>&1
} -ArgumentList $repoRoot

Write-Host "Server started in background. Launch FIFA 17 manually and trigger a connection."
Write-Host "Press ENTER after the game has tried to connect..." -ForegroundColor Green
Read-Host

# Step 6: Collect results
Write-Host "`n[6/6] Collecting results..." -ForegroundColor Yellow

# Get server output
$serverOutput = Receive-Job $serverJob 2>&1
Stop-Job $serverJob -ErrorAction SilentlyContinue
Remove-Job $serverJob -ErrorAction SilentlyContinue

# Get DLL log
$dllLog = ""
if (Test-Path $logFile) {
    $dllLog = Get-Content $logFile -Raw
}

# Write results
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$results = @"
=== TEST RESULTS ($timestamp) ===

--- SERVER OUTPUT ---
$($serverOutput -join "`n")

--- DLL LOG ---
$dllLog

--- END ---
"@

Set-Content $resultsFile $results -Encoding UTF8
Write-Host $results
Write-Host "`nResults saved to test-results.log" -ForegroundColor Green

# Commit and push results
git add test-results.log
git commit -m "Test results $timestamp"
git push 2>&1

Write-Host "`nDone! Results pushed to git." -ForegroundColor Cyan
