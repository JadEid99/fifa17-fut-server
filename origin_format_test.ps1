# Origin IPC Format Test — Single format with menu navigation
# Tests one CHALLENGE_FORMAT at a time (default: 2 = silent)

$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\origin-format-results.log"

$fmt = if ($env:TEST_FORMAT) { $env:TEST_FORMAT } else { "2" }

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KOF {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KOF]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KOF]::Enter()} }

Write-Host "=== Origin IPC Format Test (format=$fmt) ===" -ForegroundColor Cyan

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

# Kill old processes
Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 3
Remove-Item $logFile -Force -EA SilentlyContinue
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
Copy-Item "$repoRoot\commandline.txt" "$gameDir\commandline.txt" -Force

# Start servers
Write-Host "[SERVER] Starting Blaze + Origin IPC servers..." -ForegroundColor Yellow
$blazeJob = Start-Job -ScriptBlock { 
    param($r)
    $env:PREAUTH_VARIANT="full"
    $env:REDIRECT_SECURE="0"
    node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 
} -ArgumentList $repoRoot

$originJob = Start-Job -ScriptBlock { 
    param($r, $f)
    $env:CHALLENGE_FORMAT=$f
    node "$r\server-standalone\origin-ipc-server.mjs" 2>&1 
} -ArgumentList $repoRoot, $fmt
Start-Sleep 3

# Launch game
Write-Host "[GAME] Launching FIFA 17..." -ForegroundColor Yellow
Start-Process $gameExe
for($i=0;$i -lt 60;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}

# Navigate menus (game may take a while due to Origin timeout)
Write-Host "[MENU] Waiting for game window + navigating menus..." -ForegroundColor Yellow
Start-Sleep 15; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter

# Wait for DLL patches + auth injection
Write-Host "[WAIT] Waiting 45s for DLL patches + connection..." -ForegroundColor Yellow
Start-Sleep 45; FEnter; Start-Sleep 2

# Wait for connection flow
Write-Host "[WAIT] Waiting 45s for connection flow..." -ForegroundColor Yellow
Start-Sleep 45

# Collect results
Write-Host "[COLLECT] Gathering results..." -ForegroundColor Yellow
$originOut = (Receive-Job $originJob 2>&1 | Out-String).Trim()
$blazeOut = (Receive-Job $blazeJob 2>&1 | Out-String).Trim()
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}

$or1 = if($originOut.Length -gt 3000){$originOut.Substring($originOut.Length-3000)}else{$originOut}
$bs1 = if($blazeOut.Length -gt 3000){$blazeOut.Substring($blazeOut.Length-3000)}else{$blazeOut}
$dl1 = if($dllLog.Length -gt 3000){$dllLog.Substring($dllLog.Length-3000)}else{$dllLog}

$results = @"
=== Origin Format Test (format=$fmt) $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===

--- ORIGIN IPC SERVER ---
$or1

--- BLAZE SERVER ---
$bs1

--- DLL LOG ---
$dl1
"@
Set-Content $resultsFile $results -Encoding UTF8
Write-Host "`n--- ORIGIN IPC OUTPUT ---" -ForegroundColor Green
Write-Host $or1

# Cleanup
Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
Stop-Job $blazeJob,$originJob -EA SilentlyContinue
Remove-Job $blazeJob,$originJob -EA SilentlyContinue

git add -A; git commit -m "Origin format $fmt test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
