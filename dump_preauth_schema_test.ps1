# ============================================================
# FIFA 17 — PreAuthResponse TDF Schema Dump
# 
# Purpose: Extract the unknown TDF tag at PreAuthResponse+0x120
#          (the login types field) using 5 parallel Frida approaches.
#
# Usage: Run on Windows machine with FIFA 17 installed.
#        .\dump_preauth_schema_test.ps1
#
# Output: dump-preauth-results.log (committed + pushed to git)
# ============================================================

$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$dllLog = "$gameDir\fifa17_ssl_bypass.log"
$fridaScript = "$repoRoot\frida_dump_preauth_members.js"
$fridaLogFile = "$repoRoot\frida_dump_output.log"
$fridaErrFile = "$repoRoot\frida_dump_err.log"
$resultsFile = "$repoRoot\dump-preauth-results.log"

# --- Key input helpers ---
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KDUMP1 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
}
"@
function Focus {
    $p = Get-Process -Name FIFA17 -EA SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
        [KDUMP1]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 300
        return $true
    }
    return $false
}
function FEnter { if (Focus) { [KDUMP1]::Enter() } }

# --- Cleanup ---
function Kill-All {
    Write-Host "[CLEANUP] Killing old processes..." -ForegroundColor DarkGray
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  FIFA 17 — PreAuthResponse TDF Schema Dump" -ForegroundColor Cyan
Write-Host "  Goal: Find the unknown login types TDF tag" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# STEP 1: Build DLL
# ============================================================
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
Write-Host "[1/8] Building DLL..." -ForegroundColor Yellow
$buildCmd = "`"$vcvars`" `& cd /d `"$repoRoot\dll-proxy`" `& cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib"
cmd /c $buildCmd 2>&1 | Out-Null
if (-not (Test-Path "$repoRoot\dll-proxy\dinput8.dll")) {
    Write-Host "[ERROR] DLL build failed!" -ForegroundColor Red
    exit 1
}

# ============================================================
# STEP 2: Deploy files + clean old logs
# ============================================================
Write-Host "[2/8] Deploying DLL + cleaning logs..." -ForegroundColor Yellow
Kill-All
Remove-Item $dllLog -Force -EA SilentlyContinue
Remove-Item $fridaLogFile -Force -EA SilentlyContinue
Remove-Item $fridaErrFile -Force -EA SilentlyContinue
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
Copy-Item "$repoRoot\commandline.txt" "$gameDir\commandline.txt" -Force

# ============================================================
# STEP 3: Start Blaze server (plaintext)
# ============================================================
Write-Host "[3/8] Starting Blaze server..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock {
    param($r)
    $env:PREAUTH_VARIANT = "full"
    $env:REDIRECT_SECURE = "0"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1
} -ArgumentList $repoRoot
Start-Sleep 3

# ============================================================
# STEP 4: Start Origin IPC server
# ============================================================
Write-Host "[4/8] Starting Origin IPC server..." -ForegroundColor Yellow
$originJob = Start-Job -ScriptBlock {
    param($r)
    node "$r\server-standalone\origin-ipc-server.mjs" 2>&1
} -ArgumentList $repoRoot
Start-Sleep 2

# ============================================================
# STEP 5: Launch game
# ============================================================
Write-Host "[5/8] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for ($i = 0; $i -lt 30; $i++) {
    if (Get-Process -Name FIFA17 -EA SilentlyContinue) { break }
    Start-Sleep 1
}
Start-Sleep 3

$fifaProc = Get-Process -Name FIFA17 -EA SilentlyContinue
if (-not $fifaProc) {
    Write-Host "[ERROR] FIFA17 failed to start!" -ForegroundColor Red
    Stop-Job $blazeJob -EA SilentlyContinue; Remove-Job $blazeJob -EA SilentlyContinue
    Stop-Job $originJob -EA SilentlyContinue; Remove-Job $originJob -EA SilentlyContinue
    exit 1
}
$fifaPid = $fifaProc.Id
Write-Host "  FIFA17 running (PID $fifaPid)" -ForegroundColor Green

# ============================================================
# STEP 6: Attach Frida EARLY (before menu navigation)
# ============================================================
Write-Host "[6/8] Attaching Frida (PID $fifaPid)..." -ForegroundColor Yellow
$fridaProc = Start-Process -FilePath "frida" `
    -ArgumentList "-p $fifaPid -l `"$fridaScript`"" `
    -RedirectStandardOutput $fridaLogFile `
    -RedirectStandardError $fridaErrFile `
    -PassThru -NoNewWindow

Start-Sleep 5

if ($fridaProc.HasExited) {
    Write-Host "[ERROR] Frida exited immediately! Check frida_dump_err.log" -ForegroundColor Red
    $errContent = ""; if (Test-Path $fridaErrFile) { $errContent = Get-Content $fridaErrFile -Raw }
    Write-Host $errContent -ForegroundColor Red
} else {
    Write-Host "  Frida attached (PID $($fridaProc.Id))" -ForegroundColor Green
}

# ============================================================
# STEP 7: Navigate menus + wait for connection flow
# ============================================================
Write-Host "[7/8] Navigating menus..." -ForegroundColor Yellow
Start-Sleep 8
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5
FEnter

# Wait for DLL patches + Origin IPC handshake + Blaze PreAuth
Write-Host "  Waiting 35s for connection flow (DLL patches + PreAuth)..." -ForegroundColor DarkGray
Start-Sleep 35
FEnter; Start-Sleep 2

# Wait for Frida's 15-second delayed memory reads to complete
Write-Host "  Waiting 25s for Frida memory dump to complete..." -ForegroundColor DarkGray
Start-Sleep 25

# ============================================================
# STEP 8: Collect results
# ============================================================
Write-Host "[8/8] Collecting results..." -ForegroundColor Yellow

# Stop Frida
if (-not $fridaProc.HasExited) {
    Stop-Process -Id $fridaProc.Id -Force -EA SilentlyContinue
}
Start-Sleep 2

# Read Frida output
$fridaOut = ""
if (Test-Path $fridaLogFile) { $fridaOut = Get-Content $fridaLogFile -Raw }
$fridaErr = ""
if (Test-Path $fridaErrFile) { $fridaErr = Get-Content $fridaErrFile -Raw }
# Frida sometimes writes to stderr instead of stdout
if ($fridaErr.Length -gt $fridaOut.Length) { $fridaOut = $fridaErr }

# Read server logs
$blazeOut = (Receive-Job $blazeJob 2>&1 | Out-String).Trim()
$originOut = (Receive-Job $originJob 2>&1 | Out-String).Trim()
$dllContent = ""; if (Test-Path $dllLog) { $dllContent = Get-Content $dllLog -Raw }

# Kill everything
Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
Stop-Job $blazeJob -EA SilentlyContinue; Remove-Job $blazeJob -EA SilentlyContinue
Stop-Job $originJob -EA SilentlyContinue; Remove-Job $originJob -EA SilentlyContinue

# ============================================================
# Analyze + classify
# ============================================================
$verdict = "NO_DATA"
if ($fridaOut -match "CANDIDATE PreAuthResponse schema") { $verdict = "SCHEMA_FOUND" }
elseif ($fridaOut -match "UNKNOWN") { $verdict = "UNKNOWN_TAG_FOUND" }
elseif ($fridaOut -match "PreAuthHandler.*ENTERED") { $verdict = "PREAUTH_HOOKED" }
elseif ($fridaOut -match "\[DUMP\]") { $verdict = "FRIDA_RUNNING" }
elseif ($fridaOut.Length -lt 50) { $verdict = "FRIDA_NO_OUTPUT" }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  RESULT: $verdict" -ForegroundColor $(
    if ($verdict -eq "SCHEMA_FOUND") { "Green" }
    elseif ($verdict -match "UNKNOWN_TAG|PREAUTH_HOOKED") { "Yellow" }
    else { "Red" }
)
Write-Host "  Frida output: $($fridaOut.Length) chars" -ForegroundColor DarkGray
Write-Host "============================================================" -ForegroundColor Cyan

# ============================================================
# Save results
# ============================================================

# Trim logs to reasonable sizes for the results file
$blazeTail = if ($blazeOut.Length -gt 5000) { $blazeOut.Substring($blazeOut.Length - 5000) } else { $blazeOut }
$originTail = if ($originOut.Length -gt 3000) { $originOut.Substring($originOut.Length - 3000) } else { $originOut }
$dllTail = if ($dllContent.Length -gt 3000) { $dllContent.Substring($dllContent.Length - 3000) } else { $dllContent }
# Keep full Frida output — this is the primary data we need
$fridaFull = $fridaOut

$results = @"
============================================================
FIFA 17 — PreAuthResponse TDF Schema Dump
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Verdict: $verdict
============================================================

=== FRIDA OUTPUT (FULL — $($fridaFull.Length) chars) ===
$fridaFull

=== ORIGIN IPC SERVER (last 3000 chars) ===
$originTail

=== BLAZE SERVER (last 5000 chars) ===
$blazeTail

=== DLL LOG (last 3000 chars) ===
$dllTail
"@

Set-Content $resultsFile $results -Encoding UTF8
Write-Host ""
Write-Host "Results saved to: dump-preauth-results.log" -ForegroundColor Green

# Also save the raw Frida output separately for detailed analysis
Set-Content "$repoRoot\frida_dump_raw.log" $fridaOut -Encoding UTF8
Write-Host "Raw Frida output: frida_dump_raw.log" -ForegroundColor Green

# ============================================================
# Git push
# ============================================================
Write-Host ""
Write-Host "Pushing to git..." -ForegroundColor Yellow
git add -A 2>&1 | Out-Null
git commit -m "PreAuth schema dump $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$verdict]" 2>&1 | Out-Null
git push 2>&1 | Out-Null

Write-Host ""
Write-Host "Done. Pull the repo and check dump-preauth-results.log" -ForegroundColor Cyan
