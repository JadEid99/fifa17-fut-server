# Batch v29: secure=0 vs secure=1 - game disconnects regardless of PreAuth response
# v28 proved the issue is NOT the PreAuth format. Testing if main server needs TLS.
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

Write-Host "=== BATCH v28: Multi-variant PreAuth ===" -ForegroundColor Cyan

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

# Test variants - test secure=0 vs secure=1 in redirect
$variants = @(
    @{name="secure0_full"; secure="0"; preauth="full"},
    @{name="secure1_full"; secure="1"; preauth="full"}
)
$results = "=== BATCH v29 ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ===`n"

foreach ($v in $variants) {
    Write-Host "[$($v.name)] Testing..." -ForegroundColor Yellow
    Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 1
    $sj = Start-Job -ScriptBlock { param($r,$pa,$sec); $env:PREAUTH_VARIANT=$pa; $env:REDIRECT_SECURE=$sec; node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot,$v.preauth,$v.secure
    Start-Sleep 2; FQ; Start-Sleep 30
    $so = (Receive-Job $sj 2>&1 | Out-String).Trim()
    Stop-Job $sj -EA SilentlyContinue; Remove-Job $sj -EA SilentlyContinue
    FEnter; Start-Sleep 2
    
    $r1 = "UNKNOWN"
    if ($so -match "Main.*Session 2") { $r1 = "SECOND_CONNECTION" }
    elseif ($so -match "Main.*-> PostAuth") { $r1 = "POSTAUTH" }
    elseif ($so -match "Main.*-> Login") { $r1 = "LOGIN" }
    elseif ($so -match "Main.*TLS detected") { $r1 = "MAIN_TLS" }
    elseif ($so -match "Main.*-> PreAuth") { $r1 = "PREAUTH_ONLY" }
    elseif ($so -match "Main.*Session.*connected") { $r1 = "CONNECTED" }
    elseif ($so -match "HANDSHAKE COMPLETE") { $r1 = "HANDSHAKE_ONLY" }
    elseif ($so -match "TIMEOUT") { $r1 = "TIMEOUT" }
    
    Write-Host "  [$($v.name)] -> $r1" -ForegroundColor $(if($r1 -match "SECOND|POST|LOGIN|MAIN_TLS"){"Green"}elseif($r1 -match "PREAUTH|CONNECTED"){"Yellow"}else{"Red"})
    
    $tail = if($so.Length -gt 1200){$so.Substring($so.Length-1200)}else{$so}
    $results += "[$($v.name)] $r1`nSERVER_TAIL: $tail`n---`n"
}

$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw; if($dllLog.Length -gt 500){$dllLog=$dllLog.Substring(0,500)}}
$results += "DLL:`n$dllLog`n"
Set-Content $resultsFile $results -Encoding UTF8

git add -A; git commit -m "Batch v29: secure=0 vs secure=1 $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
