# Login Type Injection Test — dumps the PreAuthResponse TDF member info table
#
# This tells us the exact TDF tag name for the login types field at offset +0x120.
# The game must be running (past splash screen) for the data to be initialized.
#
# Flow:
#   1. Build DLL, start servers, launch game
#   2. Wait for game to fully initialize
#   3. Attach Frida with login inject script (one-shot, exits immediately)
#   4. Collect output, push to git

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
public class KSD {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
}
"@
function Focus {
    $p = Get-Process -Name FIFA17 -EA SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
        [KSD]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 300
        return $true
    }
    return $false
}
function FEnter { if (Focus) { [KSD]::Enter() } }

function Kill-All {
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node  -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Get-Process -Name frida -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
}

Write-Host "=== Login Type Injection ===" -ForegroundColor Cyan

# Clean slate
Kill-All
Remove-Item $dllLogFile   -Force -EA SilentlyContinue
Remove-Item $fridaLogFile -Force -EA SilentlyContinue
Remove-Item $fridaErrFile -Force -EA SilentlyContinue

# Build DLL
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

# Start servers
Write-Host "[BLAZE] Starting Blaze server..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock {
    param($r)
    $env:PREAUTH_VARIANT = "full"
    $env:REDIRECT_SECURE = "0"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1
} -ArgumentList $repoRoot
Start-Sleep 3

Write-Host "[ORIGIN] Starting Origin IPC server..." -ForegroundColor Yellow
$originJob = Start-Job -ScriptBlock {
    param($r)
    node "$r\server-standalone\origin-ipc-server.mjs" 2>&1
} -ArgumentList $repoRoot
Start-Sleep 2

# Launch game
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for ($i = 0; $i -lt 30; $i++) {
    if (Get-Process -Name FIFA17 -EA SilentlyContinue) { break }
    Start-Sleep 1
}

$fifaProc = Get-Process -Name FIFA17 -EA SilentlyContinue
if (-not $fifaProc) {
    Write-Host "[ERROR] FIFA17 did not start!" -ForegroundColor Red
    Kill-All; exit 1
}
$fifaPid = $fifaProc.Id
Write-Host "[GAME] FIFA17 PID = $fifaPid" -ForegroundColor Green

# Navigate past splash/menus so the game fully initializes
Write-Host "[MENU] Pressing Enter through menus..." -ForegroundColor Yellow
Start-Sleep 8
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5
FEnter; Start-Sleep 5

# Wait for DLL patches + Origin IPC + Blaze PreAuth to complete
Write-Host "[WAIT] Waiting 25s for full initialization..." -ForegroundColor Yellow
Start-Sleep 25

# Attach Frida with login inject (one-shot — script runs and exits)
Write-Host "[FRIDA] Dumping PreAuth schema from PID $fifaPid..." -ForegroundColor Yellow
$fridaProc = Start-Process -FilePath "frida" `
    -ArgumentList "-p $fifaPid -l `"$fridaScript`"" `
    -RedirectStandardOutput $fridaLogFile `
    -RedirectStandardError  $fridaErrFile `
    -PassThru -NoNewWindow

# The login inject script hooks functions and waits for PreAuth.
# Give it 60 seconds for the full connection flow.
Start-Sleep 60
Stop-Process -Id $fridaProc.Id -Force -EA SilentlyContinue
Start-Sleep 2

# Collect output
$fridaOut = ""
if (Test-Path $fridaLogFile) { $fridaOut = Get-Content $fridaLogFile -Raw }
$fridaErr = ""
if (Test-Path $fridaErrFile) { $fridaErr = Get-Content $fridaErrFile -Raw }
# Use whichever has more content (Frida sometimes writes to stderr)
if ($fridaErr.Length -gt $fridaOut.Length) { $fridaOut = $fridaErr }

$dllLog = ""
if (Test-Path $dllLogFile) { $dllLog = Get-Content $dllLogFile -Raw }

# Save results
$report = @"
========================================================================
Login Type Injection Results
Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
========================================================================

--- FRIDA SCHEMA DUMP ---
$fridaOut

--- FRIDA ERRORS ---
$fridaErr

--- DLL LOG (last 3000) ---
$(if ($dllLog.Length -gt 3000) { $dllLog.Substring($dllLog.Length - 3000) } else { $dllLog })
"@
Set-Content $resultsFile $report -Encoding UTF8
Write-Host "[SAVED] $resultsFile ($([int]($report.Length/1024)) KB)" -ForegroundColor Green

# Cleanup
Stop-Job $blazeJob   -EA SilentlyContinue; Remove-Job $blazeJob  -EA SilentlyContinue
Stop-Job $originJob  -EA SilentlyContinue; Remove-Job $originJob -EA SilentlyContinue
Kill-All

# Push
Write-Host "[GIT] Committing and pushing..." -ForegroundColor Yellow
Push-Location $repoRoot
git add -A | Out-Null
git commit -m "login inject $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-Null
git push 2>&1 | Out-Null
Pop-Location

Write-Host "Done." -ForegroundColor Cyan
