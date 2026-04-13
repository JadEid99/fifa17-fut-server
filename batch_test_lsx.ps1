# Batch test with LSX Origin SDK Server
# This test runs BOTH the Blaze server AND the LSX Origin server
# The LSX server replaces the STP emulator on port 4216
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSE2 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSE2]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSE2]::Enter()} }
function FQ { if(Focus){[KSE2]::Q()} }
function Kill-All { 
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    # Kill anything on port 4216 (STP emulator)
    $p4216 = Get-NetTCPConnection -LocalPort 4216 -EA SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($pid in $p4216) {
        if ($pid -gt 0) { Stop-Process -Id $pid -Force -EA SilentlyContinue }
    }
    Start-Sleep 3
}

Write-Host "=== BATCH: LSX Origin SDK Server Test ===" -ForegroundColor Cyan

# Build + deploy DLL
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
cmd /c "`"$vcvars`" && cd /d `"$repoRoot\dll-proxy`" && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib 2>&1" | Out-Null
Kill-All
Remove-Item $logFile -Force -EA SilentlyContinue
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force

# Step 1: Disable STP emulator and start our LSX server
# The STP emulator handles Denuvo licensing but NOT Origin auth.
# Our LSX server handles both the LSX handshake AND Origin auth.
Write-Host "[LSX] Preparing LSX Origin SDK server..." -ForegroundColor Yellow

# Kill anything on port 4216
$p4216 = Get-NetTCPConnection -LocalPort 4216 -EA SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
foreach ($pid in $p4216) {
    if ($pid -gt 0) { Stop-Process -Id $pid -Force -EA SilentlyContinue }
}
Start-Sleep 1

# Rename STP emulator to disable it (our LSX server replaces it)
$stpDll = "$gameDir\stp-origin_emu.dll"
$stpBak = "$gameDir\stp-origin_emu.dll.bak"
if (Test-Path $stpDll) {
    Rename-Item $stpDll $stpBak -Force -EA SilentlyContinue
    Write-Host "[LSX] Renamed stp-origin_emu.dll -> .bak" -ForegroundColor Yellow
}

# Start LSX server BEFORE the game (game connects at startup)
$lsxJob = Start-Job -ScriptBlock { 
    param($r)
    node "$r\server-standalone\lsx-origin-server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 2

$lsxOut = Receive-Job $lsxJob 2>&1 | Out-String
if ($lsxOut -match "listening") {
    Write-Host "[LSX] Server started on port 4216" -ForegroundColor Green
} else {
    Write-Host "[LSX] Server output: $lsxOut" -ForegroundColor Red
}

# Step 2: Launch game
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}
Start-Sleep 10; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter
Start-Sleep 10; FEnter; Start-Sleep 2

# Step 3: Start Blaze server
Write-Host "[BLAZE] Starting Blaze server..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock { 
    param($r)
    $env:PREAUTH_VARIANT="full"
    $env:REDIRECT_SECURE="1"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 2

# Step 4: Trigger connection attempt
Write-Host "[TEST] Triggering connection (Q key)..." -ForegroundColor Yellow
FQ
Start-Sleep 30

# Step 5: Collect results
$blazeOut = (Receive-Job $blazeJob 2>&1 | Out-String).Trim()
$lsxOut2 = (Receive-Job $lsxJob 2>&1 | Out-String).Trim()

# Classify Blaze result
$r1 = "UNKNOWN"
if ($blazeOut -match "Main.*Session 2") { $r1 = "SECOND_CONNECTION" }
elseif ($blazeOut -match "Blaze-Enc.*comp=0x0001") { $r1 = "AUTH_COMPONENT" }
elseif ($blazeOut -match "Main.*-> Login") { $r1 = "LOGIN" }
elseif ($blazeOut -match "Main.*-> PostAuth") { $r1 = "POSTAUTH" }
elseif ($blazeOut -match "Blaze-Enc.*Sent encrypted reply") { $r1 = "PREAUTH_REPLIED" }
elseif ($blazeOut -match "HANDSHAKE COMPLETE") { $r1 = "MAIN_TLS_COMPLETE" }
elseif ($blazeOut -match "Main.*TLS detected") { $r1 = "MAIN_TLS_STARTED" }
elseif ($blazeOut -match "Alert") { $r1 = "ALERT" }
elseif ($blazeOut -match "Main.*Session.*connected") { $r1 = "CONNECTED" }
elseif ($blazeOut -match "ECONNRESET") { $r1 = "ECONNRESET" }

# Classify LSX result
$lsxResult = "NO_ACTIVITY"
if ($lsxOut2 -match "GetAuthCode") { $lsxResult = "AUTH_CODE_REQUESTED" }
elseif ($lsxOut2 -match "Login event") { $lsxResult = "LOGIN_SENT" }
elseif ($lsxOut2 -match "Handshake complete") { $lsxResult = "HANDSHAKE_OK" }
elseif ($lsxOut2 -match "ChallengeResponse") { $lsxResult = "CHALLENGE_RECEIVED" }
elseif ($lsxOut2 -match "Client connected") { $lsxResult = "CONNECTED" }

Write-Host ""
Write-Host "=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Blaze: $r1" -ForegroundColor $(if($r1 -match "LOGIN|AUTH_COMPONENT"){"Green"}elseif($r1 -match "POSTAUTH|PREAUTH"){"Yellow"}else{"Red"})
Write-Host "LSX:   $lsxResult" -ForegroundColor $(if($lsxResult -match "AUTH_CODE"){"Green"}elseif($lsxResult -match "HANDSHAKE|LOGIN"){"Yellow"}else{"Red"})

# Dismiss error dialog
FEnter; Start-Sleep 2

# Save results
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}
$bs1 = if($blazeOut.Length -gt 3000){$blazeOut.Substring($blazeOut.Length-3000)}else{$blazeOut}
$ls1 = if($lsxOut2.Length -gt 3000){$lsxOut2.Substring($lsxOut2.Length-3000)}else{$lsxOut2}

$results = @"
=== LSX Origin SDK Test ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ===
BLAZE RESULT: $r1
LSX RESULT: $lsxResult

--- BLAZE SERVER LOG ---
$bs1

--- LSX SERVER LOG ---
$ls1

--- DLL LOG ---
$dllLog
"@
Set-Content $resultsFile $results -Encoding UTF8

# Cleanup
Stop-Job $blazeJob -EA SilentlyContinue; Remove-Job $blazeJob -EA SilentlyContinue
Stop-Job $lsxJob -EA SilentlyContinue; Remove-Job $lsxJob -EA SilentlyContinue

# Restore STP emulator
if (Test-Path $stpBak) {
    Rename-Item $stpBak $stpDll -Force -EA SilentlyContinue
    Write-Host "[CLEANUP] Restored stp-origin_emu.dll" -ForegroundColor Yellow
}

# Git push
git add -A; git commit -m "LSX Origin SDK test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
