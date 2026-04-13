# Frida Login Flow Trace - Automated v2
# Launches game, attaches Frida EARLY, triggers connection, collects results

$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$fridaScript = "$repoRoot\frida_force_login.js"
$fridaResults = "$repoRoot\frida_results.txt"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KF2 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KF2]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KF2]::Enter()} }
function FQ { if(Focus){[KF2]::Q()} }

Write-Host "=== Frida Deep RPC Trace v2 ===" -ForegroundColor Cyan

# Kill old processes
Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 3

# Build + deploy DLL
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
Write-Host "[BUILD] Compiling DLL..." -ForegroundColor Yellow
cmd /c "`"$vcvars`" && cd /d `"$repoRoot\dll-proxy`" && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib 2>&1" | Out-Null
Remove-Item $logFile -Force -EA SilentlyContinue
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force

# Start Blaze server
Write-Host "[BLAZE] Starting Blaze server..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock { 
    param($r)
    $env:PREAUTH_VARIANT="full"
    $env:REDIRECT_SECURE="1"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 3

# Launch game
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
# Wait for game to start
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}
Start-Sleep 3

# Attach Frida VERY EARLY - before any menu navigation
$fifaProc = Get-Process -Name FIFA17 -EA SilentlyContinue
if (-not $fifaProc) { Write-Host "[ERROR] FIFA17 not running!" -ForegroundColor Red; exit 1 }
$fifaPid = $fifaProc.Id
Write-Host "[FRIDA] Attaching to FIFA17 PID $fifaPid..." -ForegroundColor Yellow

# Run Frida in background, capture output to file directly
$fridaLogFile = "$repoRoot\frida_live.log"
Remove-Item $fridaLogFile -Force -EA SilentlyContinue
$fridaJob = Start-Job -ScriptBlock {
    param($fpid, $script, $logPath)
    $output = frida -p $fpid -l $script 2>&1 | Out-String
    Set-Content $logPath $output -Encoding UTF8
    return $output
} -ArgumentList $fifaPid, $fridaScript, $fridaLogFile
Start-Sleep 5

# Navigate menus (Frida is already attached)
Write-Host "[MENU] Navigating menus..." -ForegroundColor Yellow
FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter

# Wait for first connection + auth injection
Write-Host "[WAIT] Waiting for first connection attempt (20s)..." -ForegroundColor Yellow
Start-Sleep 20; FEnter; Start-Sleep 2

# Trigger connection with Q
Write-Host "[TEST] Pressing Q to trigger connection..." -ForegroundColor Yellow
FQ

# Wait longer for the full flow to complete
Write-Host "[WAIT] Waiting 45s for full connection flow..." -ForegroundColor Yellow
Start-Sleep 45

# Collect Frida output
Write-Host "[COLLECT] Gathering results..." -ForegroundColor Yellow
Stop-Job $fridaJob -EA SilentlyContinue
$fridaOut = (Receive-Job $fridaJob 2>&1 | Out-String).Trim()
Remove-Job $fridaJob -EA SilentlyContinue

# Also try to read from the log file
if (Test-Path $fridaLogFile) {
    $fridaFileOut = Get-Content $fridaLogFile -Raw
    if ($fridaFileOut.Length -gt $fridaOut.Length) {
        $fridaOut = $fridaFileOut
    }
}

# Collect Blaze output
$blazeOut = (Receive-Job $blazeJob 2>&1 | Out-String).Trim()
Stop-Job $blazeJob -EA SilentlyContinue
Remove-Job $blazeJob -EA SilentlyContinue

# DLL log
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}

# Save Frida results
Set-Content $fridaResults $fridaOut -Encoding UTF8
Write-Host "[FRIDA] Results saved to frida_results.txt ($($fridaOut.Length) chars)" -ForegroundColor Green

# Save combined results
$bs1 = if($blazeOut.Length -gt 3000){$blazeOut.Substring($blazeOut.Length-3000)}else{$blazeOut}
$dl1 = if($dllLog.Length -gt 3000){$dllLog.Substring($dllLog.Length-3000)}else{$dllLog}
$fr1 = if($fridaOut.Length -gt 5000){$fridaOut.Substring($fridaOut.Length-5000)}else{$fridaOut}

$results = @"
=== Frida Deep RPC Trace v2 ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ===

--- FRIDA OUTPUT (last 5000 chars) ---
$fr1

--- BLAZE SERVER LOG (last 3000 chars) ---
$bs1

--- DLL LOG (last 3000 chars) ---
$dl1
"@
Set-Content $resultsFile $results -Encoding UTF8

# Push
git add -A; git commit -m "Frida deep RPC trace $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
