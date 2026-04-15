# Batch test: FIFA 17 Private Server
# Builds DLL, starts server, launches game, triggers connection, collects results

$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSE4 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSE4]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSE4]::Enter()} }
function FQ { if(Focus){[KSE4]::Q()} }
function Kill-All { 
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
}

Write-Host "=== FIFA 17 Private Server Test ===" -ForegroundColor Cyan

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
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
Copy-Item "$repoRoot\commandline.txt" "$gameDir\commandline.txt" -Force

# Start Blaze server (plaintext main server)
Write-Host "[SERVER] Starting Blaze server..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock { 
    param($r)
    $env:PREAUTH_VARIANT="full"
    $env:REDIRECT_SECURE="0"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 
} -ArgumentList $repoRoot
Start-Sleep 3

# Launch game
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}

# Navigate menus
Write-Host "[MENU] Navigating menus..." -ForegroundColor Yellow
Start-Sleep 10; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter

# Wait for first auto-connection + DLL auth injection to complete
Write-Host "[WAIT] Waiting 30s for DLL patches + auth injection..." -ForegroundColor Yellow
Start-Sleep 30; FEnter; Start-Sleep 2

# Trigger connection with Q (disabled — connection happens automatically at launch)
# Write-Host "[TEST] Pressing Q to trigger connection..." -ForegroundColor Yellow
# FQ

# Wait for the connection flow
Write-Host "[WAIT] Waiting 30s for connection flow..." -ForegroundColor Yellow
Start-Sleep 30

# Collect results
Write-Host "[COLLECT] Gathering results..." -ForegroundColor Yellow
$blazeOut = (Receive-Job $blazeJob 2>&1 | Out-String).Trim()

# Classify result
$r1 = "UNKNOWN"
if ($blazeOut -match "PostAuth") { $r1 = "POSTAUTH" }
elseif ($blazeOut -match "Login/Auth cmd=0x28|Login/Auth cmd=0x32|Login/Auth cmd=0x98") { $r1 = "LOGIN" }
elseif ($blazeOut -match "Auth cmd=0xa.*CreateAccount") { $r1 = "CREATE_ACCOUNT" }
elseif ($blazeOut -match "FetchClientConfig") { $r1 = "FETCH_CONFIG" }
elseif ($blazeOut -match "comp=0x0009 cmd=0x0007") { $r1 = "PREAUTH" }
elseif ($blazeOut -match "Session.*connected") { $r1 = "CONNECTED" }

Write-Host ""
Write-Host "=== RESULT: $r1 ===" -ForegroundColor $(if($r1 -match "LOGIN|POSTAUTH"){"Green"}elseif($r1 -match "CREATE_ACCOUNT|FETCH_CONFIG"){"Yellow"}else{"Red"})

# Save results
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}
$bs1 = if($blazeOut.Length -gt 15000){$blazeOut.Substring($blazeOut.Length-15000)}else{$blazeOut}
$dl1 = if($dllLog.Length -gt 8000){$dllLog.Substring($dllLog.Length-8000)}else{$dllLog}

$results = @"
=== Batch Test ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ===
RESULT: $r1

--- BLAZE SERVER LOG (last 5000 chars) ---
$bs1

--- DLL LOG (last 8000 chars) ---
$dl1
"@
Set-Content $resultsFile $results -Encoding UTF8

# Cleanup
Stop-Job $blazeJob -EA SilentlyContinue; Remove-Job $blazeJob -EA SilentlyContinue

git add -A; git commit -m "test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
