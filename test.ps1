# FIFA 17 FUT Server - Automated Test Script
# Run this from the repo root on your Windows PC
# Usage: .\test.ps1

$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\test-results.log"

# Helper: send Enter key to FIFA 17 using low-level keybd_event
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KeySender {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const byte VK_RETURN = 0x0D;
    public const byte VK_SPACE = 0x20;
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public static void PressEnter() {
        keybd_event(VK_RETURN, 0x1C, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(50);
        keybd_event(VK_RETURN, 0x1C, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }
    public static void PressSpace() {
        keybd_event(VK_SPACE, 0x39, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(50);
        keybd_event(VK_SPACE, 0x39, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }
}
"@

function Send-EnterToFIFA {
    $proc = Get-Process -Name FIFA17 -ErrorAction SilentlyContinue
    if ($proc -and $proc.MainWindowHandle -ne [IntPtr]::Zero) {
        [KeySender]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 200
        [KeySender]::PressEnter()
    }
}

Write-Host "=== FIFA 17 FUT Server Test ===" -ForegroundColor Cyan

# Step 1: Pull latest changes
Write-Host "`n[1/7] Pulling latest changes..." -ForegroundColor Yellow
git pull 2>&1 | Tee-Object -Variable gitOutput

# Step 2: Kill FIFA 17 and any existing server
Write-Host "`n[2/7] Stopping FIFA 17 and old servers..." -ForegroundColor Yellow
Stop-Process -Name FIFA17 -Force -ErrorAction SilentlyContinue
Get-Process -Name node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$portProc = Get-NetTCPConnection -LocalPort 42230 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -ErrorAction SilentlyContinue
if ($portProc) { Stop-Process -Id $portProc -Force -ErrorAction SilentlyContinue }
Start-Sleep 3

# Step 3: Build DLL
Write-Host "`n[3/7] Building DLL..." -ForegroundColor Yellow
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
} else {
    Write-Host "ERROR: Visual Studio Build Tools not found!" -ForegroundColor Red
}

# Step 4: Deploy DLL and clean log
Write-Host "`n[4/7] Deploying..." -ForegroundColor Yellow
Remove-Item $logFile -Force -ErrorAction SilentlyContinue
if (Test-Path "$repoRoot\dll-proxy\dinput8.dll") {
    Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
    Write-Host "DLL copied to game directory"
} else {
    Write-Host "ERROR: dinput8.dll not found after build!" -ForegroundColor Red
}

# Step 5: Start server
Write-Host "`n[5/7] Starting server..." -ForegroundColor Yellow
$serverJob = Start-Job -ScriptBlock {
    param($repoRoot)
    Set-Location $repoRoot
    node "$repoRoot\server-standalone\server.mjs" 2>&1
} -ArgumentList $repoRoot
Start-Sleep 2

# Step 6: Launch FIFA 17 and auto-navigate menus
Write-Host "`n[6/7] Launching FIFA 17 and navigating menus..." -ForegroundColor Yellow
Start-Process $gameExe
Write-Host "  Waiting for game to load..."

# Wait for FIFA17 process to appear
$timeout = 30
for ($i = 0; $i -lt $timeout; $i++) {
    if (Get-Process -Name FIFA17 -ErrorAction SilentlyContinue) { break }
    Start-Sleep 1
}

# Launch sequence: loading(10s) -> language(enter) -> loading(5s) -> cutscene(enter) -> page(enter) -> settings(enter) -> connection test
Write-Host "  10s - initial loading..."
Start-Sleep 10
Write-Host "  Enter - language selection"
Send-EnterToFIFA
Start-Sleep 5
Write-Host "  Enter - skip cutscene"
Send-EnterToFIFA
Start-Sleep 5
Write-Host "  Enter - next page"
Send-EnterToFIFA
Start-Sleep 5
Write-Host "  Enter - select settings"
Send-EnterToFIFA
Start-Sleep 5
Write-Host "  Extra enters just in case..."
Send-EnterToFIFA
Start-Sleep 3
Send-EnterToFIFA

Write-Host "  Waiting 30s for connection attempt..." -ForegroundColor Green
Start-Sleep 30

# Step 7: Collect results
Write-Host "`n[7/7] Collecting results..." -ForegroundColor Yellow

$serverOutput = Receive-Job $serverJob 2>&1
Stop-Job $serverJob -ErrorAction SilentlyContinue
Remove-Job $serverJob -ErrorAction SilentlyContinue

$dllLog = ""
if (Test-Path $logFile) {
    $dllLog = Get-Content $logFile -Raw
}

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

git add test-results.log
git commit -m "Test results $timestamp"
git push 2>&1

Write-Host "`nDone! Results pushed to git." -ForegroundColor Cyan
