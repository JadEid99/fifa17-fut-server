# Flow Trace Test - passive observation run for diagnosing the Logout decision.
#
# This is a passive instrumentation run — the Frida script does NOT patch anything.
# It just logs every key function in the auth chain to identify the exact
# point where the game decides to send Logout instead of Login.
#
# Flow:
#   1. Build DLL (with all current patches)
#   2. Start Blaze server + Origin IPC server
#   3. Launch game
#   4. Attach Frida with frida_flow_trace.js (passive — no patches)
#   5. Navigate menus, trigger connection
#   6. Wait for the Logout RPC to fire
#   7. Collect ALL logs (Frida trace, Origin IPC, Blaze, DLL)
#   8. Save to frida_trace_results.log and push to git

$repoRoot = $PSScriptRoot
$gameDir  = "D:\Games\FIFA 17"
$gameExe  = "$gameDir\FIFA17.exe"
$dllLogFile = "$gameDir\fifa17_ssl_bypass.log"

$fridaScript  = "$repoRoot\frida_flow_trace.js"
$fridaLogFile = "$repoRoot\frida_trace.log"
$fridaErrFile = "$repoRoot\frida_trace_err.log"
$resultsFile  = "$repoRoot\frida_trace_results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KFT {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q()     { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus {
    $p = Get-Process -Name FIFA17 -EA SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
        [KFT]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 300
        return $true
    }
    return $false
}
function FEnter { if (Focus) { [KFT]::Enter() } }
function FQ     { if (Focus) { [KFT]::Q() } }

function Kill-All {
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node  -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Get-Process -Name frida -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
}

Write-Host "=== FIFA 17 Flow Trace (passive observation) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Clean slate
# ---------------------------------------------------------------------------
Kill-All
Remove-Item $dllLogFile   -Force -EA SilentlyContinue
Remove-Item $fridaLogFile -Force -EA SilentlyContinue
Remove-Item $fridaErrFile -Force -EA SilentlyContinue

# ---------------------------------------------------------------------------
# 2. Build DLL
# ---------------------------------------------------------------------------
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
Write-Host "[BUILD] Compiling DLL..." -ForegroundColor Yellow
cmd /c "`"$vcvars`" && cd /d `"$repoRoot\dll-proxy`" && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib 2>&1" | Out-Null
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll"  -Force
Copy-Item "$repoRoot\commandline.txt"       "$gameDir\commandline.txt" -Force

# ---------------------------------------------------------------------------
# 3. Start servers
# ---------------------------------------------------------------------------
Write-Host "[BLAZE] Starting Blaze server (port 42230 + 10041)..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock {
    param($r)
    $env:PREAUTH_VARIANT = "full"
    $env:REDIRECT_SECURE = "0"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1
} -ArgumentList $repoRoot
Start-Sleep 3

Write-Host "[ORIGIN] Starting Origin IPC server (port 3216)..." -ForegroundColor Yellow
$originJob = Start-Job -ScriptBlock {
    param($r)
    node "$r\server-standalone\origin-ipc-server.mjs" 2>&1
} -ArgumentList $repoRoot
Start-Sleep 2

# ---------------------------------------------------------------------------
# 4. Launch game
# ---------------------------------------------------------------------------
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for ($i = 0; $i -lt 30; $i++) {
    if (Get-Process -Name FIFA17 -EA SilentlyContinue) { break }
    Start-Sleep 1
}
Start-Sleep 3

$fifaProc = Get-Process -Name FIFA17 -EA SilentlyContinue
if (-not $fifaProc) {
    Write-Host "[ERROR] FIFA17 did not start!" -ForegroundColor Red
    Kill-All
    exit 1
}
$fifaPid = $fifaProc.Id
Write-Host "[GAME] FIFA17 PID = $fifaPid" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Attach Frida with passive trace script
# ---------------------------------------------------------------------------
Write-Host "[FRIDA] Attaching passive flow trace to PID $fifaPid..." -ForegroundColor Yellow
$fridaProc = Start-Process -FilePath "frida" `
    -ArgumentList "-p $fifaPid -l `"$fridaScript`"" `
    -RedirectStandardOutput $fridaLogFile `
    -RedirectStandardError  $fridaErrFile `
    -PassThru -NoNewWindow

Start-Sleep 5

# ---------------------------------------------------------------------------
# 6. Navigate menus to trigger connection
# ---------------------------------------------------------------------------
Write-Host "[MENU] Pressing Enter through intro menus..." -ForegroundColor Yellow
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5

Write-Host "[WAIT] Letting first connection attempt run (30s)..." -ForegroundColor Yellow
Start-Sleep 30
FEnter; Start-Sleep 2

# Press Q in case the game's UI needs a manual retry trigger (matches batch_test_lsx.ps1 pattern)
Write-Host "[TRIGGER] Pressing Q to trigger retry connection..." -ForegroundColor Yellow
FQ; Start-Sleep 2

Write-Host "[WAIT] Waiting 45s for full Logout sequence to complete..." -ForegroundColor Yellow
Start-Sleep 45

# ---------------------------------------------------------------------------
# 7. Collect ALL output
# ---------------------------------------------------------------------------
Write-Host "[COLLECT] Gathering results..." -ForegroundColor Yellow

# Stop Frida gracefully
Stop-Process -Id $fridaProc.Id -Force -EA SilentlyContinue
Start-Sleep 3

# Frida output
$fridaOut = ""
if (Test-Path $fridaLogFile) { $fridaOut = Get-Content $fridaLogFile -Raw }
$fridaErr = ""
if (Test-Path $fridaErrFile) { $fridaErr = Get-Content $fridaErrFile -Raw }

# Server outputs (still running — kill them cleanly now)
$blazeOut  = (Receive-Job $blazeJob  2>&1 | Out-String).Trim()
$originOut = (Receive-Job $originJob 2>&1 | Out-String).Trim()

# DLL log
$dllLog = ""
if (Test-Path $dllLogFile) { $dllLog = Get-Content $dllLogFile -Raw }

# ---------------------------------------------------------------------------
# 8. Classify result
# ---------------------------------------------------------------------------
$verdict = "UNKNOWN"
if     ($fridaOut  -match "LoginSender")                 { $verdict = "LOGIN_SENT" }
elseif ($blazeOut  -match "cmd=0x28|cmd=0x32|cmd=0x98")  { $verdict = "LOGIN_WIRE" }
elseif ($fridaOut  -match "LOGOUT SENT")                 { $verdict = "LOGOUT_CAPTURED" }
elseif ($fridaOut  -match "LoginFallback_NoTypes")       { $verdict = "FALLBACK_NO_LOGIN_TYPES" }
elseif ($blazeOut  -match "cmd=0x46|cmd=0x0046")         { $verdict = "LOGOUT_WIRE" }
elseif ($blazeOut  -match "FetchClientConfig")           { $verdict = "FETCH_CONFIG_ONLY" }
elseif ($blazeOut  -match "PreAuth")                     { $verdict = "PREAUTH_ONLY" }

Write-Host ""
$color = if ($verdict -match "LOGIN")     { "Green" }
         elseif ($verdict -match "LOGOUT|FALLBACK") { "Yellow" }
         else { "Red" }
Write-Host "=== VERDICT: $verdict ===" -ForegroundColor $color
Write-Host ""

# ---------------------------------------------------------------------------
# 9. Save combined report
# ---------------------------------------------------------------------------
# Take generous tails since the whole point is analysis
function Tail($s, $n) {
    if ($null -eq $s) { return "" }
    if ($s.Length -gt $n) { return $s.Substring($s.Length - $n) }
    return $s
}

$report = @"
========================================================================
FIFA 17 FLOW TRACE RESULTS
Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Verdict: $verdict
========================================================================

--- FRIDA ERRORS (first, if any) ---
$(Tail $fridaErr 2000)

--- FRIDA FLOW TRACE (full) ---
$(Tail $fridaOut 60000)

--- ORIGIN IPC SERVER (last 10000) ---
$(Tail $originOut 10000)

--- BLAZE SERVER (last 10000) ---
$(Tail $blazeOut 10000)

--- DLL LOG (last 8000) ---
$(Tail $dllLog 8000)
"@
Set-Content $resultsFile $report -Encoding UTF8
Write-Host "[SAVED] $resultsFile ($([int]($report.Length/1024)) KB)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 10. Cleanup + push
# ---------------------------------------------------------------------------
Stop-Job $blazeJob   -EA SilentlyContinue
Remove-Job $blazeJob -EA SilentlyContinue
Stop-Job $originJob   -EA SilentlyContinue
Remove-Job $originJob -EA SilentlyContinue
Kill-All

Write-Host "[GIT] Committing and pushing..." -ForegroundColor Yellow
Push-Location $repoRoot
git add -A | Out-Null
git commit -m "flow trace $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') verdict=$verdict" | Out-Null
git push 2>&1 | Out-Null
Pop-Location

Write-Host "Done." -ForegroundColor Cyan
