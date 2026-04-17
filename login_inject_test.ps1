# Login Type Injection Test
#
# Identical structure to flow_trace_test.ps1 (which works), but uses
# frida_inject_login_type.js instead of frida_flow_trace.js.

$repoRoot = $PSScriptRoot
$gameDir  = "D:\Games\FIFA 17"
$gameExe  = "$gameDir\FIFA17.exe"
$dllLogFile = "$gameDir\fifa17_ssl_bypass.log"

$fridaScript  = "$repoRoot\frida_inject_login_type.js"
$fridaLogFile = "$repoRoot\login_inject.log"
$fridaErrFile = "$repoRoot\login_inject_err.log"
$resultsFile  = "$repoRoot\login_inject_results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KLI {
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
        [KLI]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 300
        return $true
    }
    return $false
}
function FEnter { if (Focus) { [KLI]::Enter() } }
function FQ     { if (Focus) { [KLI]::Q() } }

function Kill-All {
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node  -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Get-Process -Name frida -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
}

Write-Host "=== FIFA 17 Login Type Injection ===" -ForegroundColor Cyan

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
    Write-Host "[INFO] Please launch FIFA17.exe manually, then press Enter here." -ForegroundColor Yellow
    Read-Host "Press Enter after FIFA17 is running"
    $fifaProc = Get-Process -Name FIFA17 -EA SilentlyContinue
    if (-not $fifaProc) {
        Write-Host "[ERROR] Still no FIFA17 process found. Exiting." -ForegroundColor Red
        Kill-All; exit 1
    }
}
$fifaPid = $fifaProc.Id
Write-Host "[GAME] FIFA17 PID = $fifaPid" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5. Attach Frida EARLY — before menu navigation so we catch PreAuth
# ---------------------------------------------------------------------------
Write-Host "[FRIDA] Attaching login type injector to PID $fifaPid..." -ForegroundColor Yellow
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

Write-Host "[TRIGGER] Pressing Q to trigger retry connection..." -ForegroundColor Yellow
FQ; Start-Sleep 2

Write-Host "[WAIT] Waiting 45s for Login/PostAuth flow..." -ForegroundColor Yellow
Start-Sleep 45

# ---------------------------------------------------------------------------
# 7. Collect ALL output
# ---------------------------------------------------------------------------
Write-Host "[COLLECT] Gathering results..." -ForegroundColor Yellow

Stop-Process -Id $fridaProc.Id -Force -EA SilentlyContinue
Start-Sleep 3

$fridaOut = ""
if (Test-Path $fridaLogFile) { $fridaOut = Get-Content $fridaLogFile -Raw }
$fridaErr = ""
if (Test-Path $fridaErrFile) { $fridaErr = Get-Content $fridaErrFile -Raw }

$blazeOut  = (Receive-Job $blazeJob  2>&1 | Out-String).Trim()
$originOut = (Receive-Job $originJob 2>&1 | Out-String).Trim()

$dllLog = ""
if (Test-Path $dllLogFile) { $dllLog = Get-Content $dllLogFile -Raw }

# ---------------------------------------------------------------------------
# 8. Save combined report
# ---------------------------------------------------------------------------
function Tail($s, $n) {
    if ($null -eq $s) { return "" }
    if ($s.Length -gt $n) { return $s.Substring($s.Length - $n) }
    return $s
}

$report = @"
========================================================================
FIFA 17 LOGIN TYPE INJECTION RESULTS
Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
========================================================================

--- FRIDA OUTPUT ---
$fridaOut

--- FRIDA ERRORS ---
$fridaErr

--- ORIGIN IPC SERVER (last 5000) ---
$(Tail $originOut 5000)

--- BLAZE SERVER (last 10000) ---
$(Tail $blazeOut 10000)

--- DLL LOG (last 5000) ---
$(Tail $dllLog 5000)
"@
Set-Content $resultsFile $report -Encoding UTF8
Write-Host "[SAVED] $resultsFile ($([int]($report.Length/1024)) KB)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 9. Cleanup + push
# ---------------------------------------------------------------------------
Stop-Job $blazeJob   -EA SilentlyContinue
Remove-Job $blazeJob -EA SilentlyContinue
Stop-Job $originJob   -EA SilentlyContinue
Remove-Job $originJob -EA SilentlyContinue
Kill-All

Write-Host "[GIT] Committing and pushing..." -ForegroundColor Yellow
Push-Location $repoRoot
git add -A | Out-Null
git commit -m "login inject $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-Null
git push 2>&1 | Out-Null
Pop-Location

Write-Host "Done." -ForegroundColor Cyan
