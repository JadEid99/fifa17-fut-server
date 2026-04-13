# Batch test: LSX Origin SDK Server with connect() hook
# 
# Architecture:
#   Game -> connect(127.0.0.1:4216) -> DLL hook redirects to 4218
#   Our LSX proxy on 4218 -> forwards Denuvo traffic to STP on 4216
#   Our LSX proxy also injects Login event + handles GetAuthCode
#
# STP emulator stays on 4216 (Denuvo works)
# Our LSX proxy on 4218 (Origin auth works)
# DLL hooks connect() to redirect 4216 -> 4218

$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSE3 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSE3]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSE3]::Enter()} }
function FQ { if(Focus){[KSE3]::Q()} }
function Kill-All { 
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
}

Write-Host "=== BATCH: LSX Origin SDK + connect() hook ===" -ForegroundColor Cyan

# Build + deploy DLL (v58 with connect hook)
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
Write-Host "[BUILD] Compiling DLL v58..." -ForegroundColor Yellow
cmd /c "`"$vcvars`" && cd /d `"$repoRoot\dll-proxy`" && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib 2>&1" | Out-Null
Kill-All
Remove-Item $logFile -Force -EA SilentlyContinue
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force

# Step 1: Start Blaze server FIRST
Write-Host "[BLAZE] Starting Blaze server..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock { 
    param($r)
    $env:PREAUTH_VARIANT="full"
    $env:REDIRECT_SECURE="1"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 3

# Start LSX server (diagnostic only)
Write-Host "[LSX] Starting LSX server on port 4218 (diagnostic)..." -ForegroundColor Yellow
$lsxJob = Start-Job -ScriptBlock { 
    param($r)
    $env:LSX_PORT = "4218"
    node "$r\server-standalone\lsx-origin-server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 2

# Launch game
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}
Start-Sleep 10; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter
# Wait for first connection attempt + auth injection
Start-Sleep 20; FEnter; Start-Sleep 2

# Blaze server already running from before game launch
# Just trigger connection attempt
Write-Host "[TEST] Triggering connection (Q key)..." -ForegroundColor Yellow
FQ
Start-Sleep 30

# Collect results
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
elseif ($lsxOut2 -match "Injected Login") { $lsxResult = "LOGIN_INJECTED" }
elseif ($lsxOut2 -match "Handshake complete|handshake complete") { $lsxResult = "HANDSHAKE_OK" }
elseif ($lsxOut2 -match "ChallengeResponse|challenge") { $lsxResult = "CHALLENGE_RECEIVED" }
elseif ($lsxOut2 -match "Game connected|Client connected") { $lsxResult = "CONNECTED" }
elseif ($lsxOut2 -match "Redirecting|HOOK") { $lsxResult = "HOOK_ACTIVE" }

Write-Host ""
Write-Host "=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Blaze: $r1" -ForegroundColor $(if($r1 -match "LOGIN|AUTH_COMPONENT"){"Green"}elseif($r1 -match "POSTAUTH|PREAUTH"){"Yellow"}else{"Red"})
Write-Host "LSX:   $lsxResult" -ForegroundColor $(if($lsxResult -match "AUTH_CODE"){"Green"}elseif($lsxResult -match "HANDSHAKE|LOGIN"){"Yellow"}elseif($lsxResult -match "CONNECTED|CHALLENGE"){"Cyan"}else{"Red"})

FEnter; Start-Sleep 2

# Save results
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}
$bs1 = if($blazeOut.Length -gt 3000){$blazeOut.Substring($blazeOut.Length-3000)}else{$blazeOut}
$ls1 = if($lsxOut2.Length -gt 3000){$lsxOut2.Substring($lsxOut2.Length-3000)}else{$lsxOut2}

$results = @"
=== LSX + connect() hook test ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ===
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

git add -A; git commit -m "LSX connect hook test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
