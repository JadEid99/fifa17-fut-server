# Batch v19: HTTP-wrapped Blaze - game sends HTTP POST over TLS, not raw binary
# v18 revealed: decrypted data is "POST /redirector/getServerInstance HTTP/1.1"
# Need to parse HTTP, respond with XML redirect, handle main server connection
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

Write-Host "=== BATCH v19: HTTP-wrapped Blaze ===" -ForegroundColor Cyan

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

# Launch game once
Start-Process $gameExe
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}
Start-Sleep 10; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter; Start-Sleep 5; FEnter
Start-Sleep 10; FEnter; Start-Sleep 2

# Test: Fixed handshake flow
Write-Host "[1] HTTP-wrapped Blaze over TLS" -ForegroundColor Yellow
Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sj = Start-Job -ScriptBlock { param($r); node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2; FQ; Start-Sleep 40
$so1 = (Receive-Job $sj 2>&1 | Out-String).Trim()
Stop-Job $sj -EA SilentlyContinue; Remove-Job $sj -EA SilentlyContinue
FEnter; Start-Sleep 2

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$r1 = "UNKNOWN"
if ($so1 -match "Main.*Session.*connected") { $r1 = "MAIN_SERVER_CONNECTED" }
elseif ($so1 -match "Sent encrypted HTTP response") { $r1 = "HTTP_RESPONSE_SENT" }
elseif ($so1 -match "HTTP-Blaze.*GetServerInstance") { $r1 = "REDIRECT_PARSED" }
elseif ($so1 -match "Blaze-Enc.*comp=") { $r1 = "BLAZE_PACKET_PARSED" }
elseif ($so1 -match "HANDSHAKE COMPLETE") { $r1 = "HANDSHAKE_COMPLETE" }
elseif ($so1 -match "Decrypted \d+ bytes of application") { $r1 = "APP_DATA_DECRYPTED" }
elseif ($so1 -match "Alert.*level=") { $r1 = "ALERT" }
elseif ($so1 -match "Decrypted PMS") { $r1 = "KEYS_DERIVED" }
elseif ($so1 -match "ECONNRESET") { $r1 = "ECONNRESET" }
elseif ($so1 -match "TIMEOUT") { $r1 = "TIMEOUT" }
Write-Host "  -> $r1" -ForegroundColor $(if($r1 -match "MAIN_SERVER|HTTP_RESPONSE|BLAZE"){"Green"}elseif($r1 -match "REDIRECT|COMPLETE|APP_DATA"){"Yellow"}else{"Red"})

# Capture full server output (up to 3000 chars for detailed diagnostics)
$ss1 = if($so1.Length -gt 3000){$so1.Substring($so1.Length-3000)}else{$so1}
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}
$results = "=== BATCH v19 ($timestamp) ===`n[1] HTTP-Blaze | $r1`nSERVER:`n$ss1`nDLL:`n$dllLog`n"
Set-Content $resultsFile $results -Encoding UTF8

git add -A; git commit -m "Batch v19: HTTP-wrapped Blaze $timestamp"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
