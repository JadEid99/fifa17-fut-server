# Batch v31: DLL v52 - permanent code patch (JNZ -> JMP) instead of flag racing
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

Write-Host "=== BATCH v31: DLL v52 permanent code patch ===" -ForegroundColor Cyan

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

# Single test with secure=1 and DLL v51
Write-Host "[1] DLL v52 code patch + secure=1" -ForegroundColor Yellow
Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$sj = Start-Job -ScriptBlock { param($r); $env:PREAUTH_VARIANT="full"; $env:REDIRECT_SECURE="1"; node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2; FQ; Start-Sleep 25
$so1 = (Receive-Job $sj 2>&1 | Out-String).Trim()
Stop-Job $sj -EA SilentlyContinue; Remove-Job $sj -EA SilentlyContinue
FEnter; Start-Sleep 2

$r1 = "UNKNOWN"
if ($so1 -match "Main.*Session 2") { $r1 = "SECOND_CONNECTION" }
elseif ($so1 -match "Blaze-Enc.*comp=0x0009 cmd=0x0008") { $r1 = "POSTAUTH" }
elseif ($so1 -match "Blaze-Enc.*comp=0x0001") { $r1 = "AUTH_COMPONENT" }
elseif ($so1 -match "Blaze-Enc.*Sent encrypted reply") { $r1 = "PREAUTH_REPLIED" }
elseif ($so1 -match "Blaze-Enc.*comp=0x0009 cmd=0x0007") { $r1 = "PREAUTH_PARSED" }
elseif ($so1 -match "Main.*-> PostAuth") { $r1 = "POSTAUTH" }
elseif ($so1 -match "Main.*-> Login") { $r1 = "LOGIN" }
elseif ($so1 -match "Main.*-> PreAuth") { $r1 = "PREAUTH_HANDLED" }
elseif ($so1 -match "Main.*HANDSHAKE COMPLETE") { $r1 = "MAIN_TLS_COMPLETE" }
elseif ($so1 -match "Main.*TLS detected") { $r1 = "MAIN_TLS_STARTED" }
elseif ($so1 -match "Alert.*46") { $r1 = "CERT_REJECTED" }
elseif ($so1 -match "Alert") { $r1 = "ALERT" }
elseif ($so1 -match "Main.*Session.*connected") { $r1 = "CONNECTED" }
elseif ($so1 -match "ECONNRESET") { $r1 = "ECONNRESET" }
Write-Host "  -> $r1" -ForegroundColor $(if($r1 -match "POSTAUTH|LOGIN|PREAUTH|MAIN_TLS_COMPLETE"){"Green"}elseif($r1 -match "MAIN_TLS|CONNECTED"){"Yellow"}else{"Red"})

$ss1 = if($so1.Length -gt 3000){$so1.Substring($so1.Length-3000)}else{$so1}
$dllLog = ""; if(Test-Path $logFile){$dllLog = Get-Content $logFile -Raw}
$results = "=== BATCH v31 ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ===`n[1] DLL v52 code patch | $r1`nSERVER:`n$ss1`nDLL:`n$dllLog`n"
Set-Content $resultsFile $results -Encoding UTF8

git add -A; git commit -m "Batch v31: DLL v52 code patch $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
