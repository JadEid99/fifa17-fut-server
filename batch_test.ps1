# Batch v14: DLL-based patching (patches applied before first connection)
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSC {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSC]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSC]::Enter()} }
function FQ { if(Focus){[KSC]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }

Write-Host "=== BATCH v14: DLL-based SSL bypass ===" -ForegroundColor Cyan

# Step 1: Build DLL
Write-Host "[1] Building DLL..." -ForegroundColor Yellow
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
$buildOutput = cmd /c "`"$vcvars`" && cd /d `"$repoRoot\dll-proxy`" && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib 2>&1"
Write-Host $buildOutput

# Step 2: Deploy
Write-Host "[2] Deploying..." -ForegroundColor Yellow
Kill-All
Remove-Item $logFile -Force -EA SilentlyContinue
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
Write-Host "DLL deployed."

# Step 3: Start server
Write-Host "[3] Starting server..." -ForegroundColor Yellow
$sj = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2

# Step 4: Launch game (DLL patches will apply automatically during Denuvo unpack)
Write-Host "[4] Launching game (DLL will patch during load)..." -ForegroundColor Yellow
Start-Process $gameExe
for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}

# Navigate menus - the DLL is scanning and patching in the background
Start-Sleep 10; FEnter
Start-Sleep 5; FEnter
Start-Sleep 5; FEnter
Start-Sleep 5; FEnter
Start-Sleep 10; FEnter  # dismiss first connection result
Start-Sleep 2

# Step 5: Trigger connection attempt #2 (patches should be applied by now)
Write-Host "[5] Triggering connection..." -ForegroundColor Yellow
FQ
Start-Sleep 20

# Step 6: Collect results
Write-Host "[6] Collecting results..." -ForegroundColor Yellow
$so = (Receive-Job $sj 2>&1 | Out-String).Trim()
Stop-Job $sj -EA SilentlyContinue; Remove-Job $sj -EA SilentlyContinue

$dllLog = ""
if (Test-Path $logFile) { $dllLog = Get-Content $logFile -Raw }

$r = "UNKNOWN"
if ($so -match "Phase=.*received") { $r = "RECEIVED_DATA" }
if ($so -match "Handshake type: 0x10") { $r = "CLIENT_KEY_EXCHANGE" }
if ($so -match "ECONNRESET") { $r = "ECONNRESET" }
if ($so -match "TIMEOUT: No data") { $r = "TIMEOUT" }
if ($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "TIMEOUT") { $r = "HANGING" }
if ($so -eq "") { $r = "NO_CONNECTION" }

$color = switch -Regex ($r) { "CLIENT_KEY|RECEIVED" {"Green"} "HANGING|TIMEOUT" {"Yellow"} default {"Red"} }
Write-Host "RESULT: $r" -ForegroundColor $color

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$results = "=== DLL PATCH TEST ($timestamp) ===`nRESULT: $r`n`n--- DLL LOG ---`n$dllLog`n`n--- SERVER ---`n$so`n"
Set-Content $resultsFile $results -Encoding UTF8
Write-Host $results

git add batch-results.log; git commit -m "DLL patch test $timestamp"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
