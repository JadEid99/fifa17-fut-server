# Batch v16: Multiple server crypto variations
# The DLL is already built and deployed from the last run.
# We just need to test different server configurations.
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSE {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSE]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSE]::Enter()} }
function FQ { if(Focus){[KSE]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }

Write-Host "=== BATCH v16: Server crypto variations ===" -ForegroundColor Cyan

# Build + deploy DLL (same as before)
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

# Launch game once
Start-Process $gameExe
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}
Start-Sleep 10; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter
Start-Sleep 10; FEnter; Start-Sleep 2

# The server.mjs already has the SSLv3 crypto. Just run it with different flags.
# Test 1: Current SSLv3 PRF + SSLv3 Finished + SSLv3 MAC
Write-Host "[1] SSLv3 crypto (current)" -ForegroundColor Yellow
Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sj = Start-Job -ScriptBlock { param($r); node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2; FQ; Start-Sleep 20
$so1 = (Receive-Job $sj 2>&1 | Out-String).Trim()
Stop-Job $sj -EA SilentlyContinue; Remove-Job $sj -EA SilentlyContinue
FEnter; Start-Sleep 2

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$r1 = "UNKNOWN"
if ($so1 -match "Decrypted \d+ bytes of application") { $r1 = "APP_DATA_DECRYPTED" }
elseif ($so1 -match "Redirector.*comp=") { $r1 = "BLAZE_REQUEST" }
elseif ($so1 -match "Alert received") { $r1 = "ALERT_AFTER_FINISHED" }
elseif ($so1 -match "Sent encrypted Finished") { $r1 = "FINISHED_SENT" }
elseif ($so1 -match "Decrypted pre-master") { $r1 = "KEYS_DERIVED" }
elseif ($so1 -match "ECONNRESET") { $r1 = "ECONNRESET" }
elseif ($so1 -match "TIMEOUT") { $r1 = "TIMEOUT" }
Write-Host "  -> $r1" -ForegroundColor $(if($r1 -match "APP_DATA|BLAZE"){"Green"}elseif($r1 -match "FINISHED|KEYS"){"Yellow"}else{"Red"})

$ss1 = if($so1.Length -gt 600){$so1.Substring($so1.Length-600)}else{$so1}
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}
$results = "=== BATCH v16 ($timestamp) ===`n[1] SSLv3 crypto | $r1`nSERVER: $ss1`nDLL: $dllLog`n"
Set-Content $resultsFile $results -Encoding UTF8

git add batch-results.log; git commit -m "Batch v16 $timestamp"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
