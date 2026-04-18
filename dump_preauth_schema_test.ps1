# PreAuth Schema Dump: Attach Frida to FIFA 17, dump TDF member info table
# Modeled directly on batch_test_lsx.ps1 + frida_test.ps1

$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$fridaScript = "$repoRoot\frida_dump_preauth_members.js"
$fridaLogFile = "$repoRoot\frida_dump_output.log"
$fridaErrFile = "$repoRoot\frida_dump_err.log"
$resultsFile = "$repoRoot\dump-preauth-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSE5 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSE5]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSE5]::Enter()} }
function Kill-All { 
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
}

Write-Host "=== PreAuth Schema Dump ===" -ForegroundColor Cyan

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
Kill-All
Remove-Item $logFile -Force -EA SilentlyContinue
Remove-Item $fridaLogFile -Force -EA SilentlyContinue
Remove-Item $fridaErrFile -Force -EA SilentlyContinue
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
Copy-Item "$repoRoot\commandline.txt" "$gameDir\commandline.txt" -Force

# Start Blaze server
Write-Host "[SERVER] Starting Blaze server..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock { 
    param($r)
    $env:PREAUTH_VARIANT="full"
    $env:REDIRECT_SECURE="0"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 3

# Start Origin IPC server
Write-Host "[ORIGIN] Starting fake Origin IPC server..." -ForegroundColor Yellow
$originJob = Start-Job -ScriptBlock { 
    param($r)
    node "$r\server-standalone\origin-ipc-server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 2

# Launch game
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}
Start-Sleep 3

# Attach Frida EARLY - before menu navigation
$fifaProc = Get-Process -Name FIFA17 -EA SilentlyContinue
if (-not $fifaProc) { Write-Host "[ERROR] FIFA17 not running!" -ForegroundColor Red; exit 1 }
$fifaPid = $fifaProc.Id
Write-Host "[FRIDA] Attaching to PID $fifaPid ..." -ForegroundColor Yellow
$fridaProc = Start-Process -FilePath "frida" -ArgumentList "-p $fifaPid -l `"$fridaScript`"" -RedirectStandardOutput $fridaLogFile -RedirectStandardError $fridaErrFile -PassThru -NoNewWindow
Start-Sleep 5

# Navigate menus
Write-Host "[MENU] Navigating menus..." -ForegroundColor Yellow
Start-Sleep 8; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter

# Wait for DLL patches + PreAuth + Frida 15s delayed dump
Write-Host "[WAIT] Waiting 60s for connection flow + Frida dump..." -ForegroundColor Yellow
Start-Sleep 60; FEnter; Start-Sleep 2

# Collect results
Write-Host "[COLLECT] Gathering results..." -ForegroundColor Yellow
Stop-Process -Id $fridaProc.Id -Force -EA SilentlyContinue
Start-Sleep 2

# Read Frida output
$fridaOut = ""
if(Test-Path $fridaLogFile){$fridaOut = Get-Content $fridaLogFile -Raw}
$fridaErr = ""
if(Test-Path $fridaErrFile){$fridaErr = Get-Content $fridaErrFile -Raw}
if($fridaErr.Length -gt $fridaOut.Length){$fridaOut = $fridaErr}

# Read server logs
$blazeOut = (Receive-Job $blazeJob 2>&1 | Out-String).Trim()
$originOut = (Receive-Job $originJob 2>&1 | Out-String).Trim()
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}

# Classify
$r1 = "NO_DATA"
if($fridaOut -match "CANDIDATE PreAuthResponse schema"){$r1 = "SCHEMA_FOUND"}
elseif($fridaOut -match "UNKNOWN"){$r1 = "UNKNOWN_TAG_FOUND"}
elseif($fridaOut -match "PreAuthHandler.*ENTERED"){$r1 = "PREAUTH_HOOKED"}
elseif($fridaOut -match "\[DUMP\]"){$r1 = "FRIDA_RUNNING"}

Write-Host ""
Write-Host "=== RESULT: $r1 ===" -ForegroundColor $(if($r1 -eq "SCHEMA_FOUND"){"Green"}elseif($r1 -match "UNKNOWN|HOOKED|RUNNING"){"Yellow"}else{"Red"})
Write-Host "Frida output: $($fridaOut.Length) chars"

# Save results
$bs1 = if($blazeOut.Length -gt 5000){$blazeOut.Substring($blazeOut.Length-5000)}else{$blazeOut}
$os1 = if($originOut.Length -gt 3000){$originOut.Substring($originOut.Length-3000)}else{$originOut}
$dl1 = if($dllLog.Length -gt 3000){$dllLog.Substring($dllLog.Length-3000)}else{$dllLog}

$results = @"
=== PreAuth Schema Dump $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===
RESULT: $r1

--- FRIDA OUTPUT (FULL) ---
$fridaOut

--- ORIGIN IPC SERVER ---
$os1

--- BLAZE SERVER ---
$bs1

--- DLL LOG ---
$dl1
"@
Set-Content $resultsFile $results -Encoding UTF8
Set-Content "$repoRoot\frida_dump_raw.log" $fridaOut -Encoding UTF8

# Cleanup
Stop-Job $blazeJob -EA SilentlyContinue; Remove-Job $blazeJob -EA SilentlyContinue
Stop-Job $originJob -EA SilentlyContinue; Remove-Job $originJob -EA SilentlyContinue
Stop-Process -Name FIFA17 -Force -EA SilentlyContinue

git add -A; git commit -m "schema dump $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$r1]"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
