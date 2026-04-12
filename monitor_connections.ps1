$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$resultsFile = "$repoRoot\connection-monitor.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KM {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@

# Kill any existing server
Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2

Write-Host "Starting server..." -ForegroundColor Cyan
$sj = Start-Job -ScriptBlock { param($r); $env:PREAUTH_VARIANT="full"; $env:REDIRECT_SECURE="1"; node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 3

Write-Host "Pressing Q to trigger connection..." -ForegroundColor Yellow
$p = Get-Process -Name FIFA17 -EA SilentlyContinue
if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
    [KM]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
    Start-Sleep -Milliseconds 300
    [KM]::Q()
}

Write-Host "Monitoring connections for 40 seconds..." -ForegroundColor Yellow
$log = ""
for ($i = 0; $i -lt 80; $i++) {
    Start-Sleep -Milliseconds 500
    $ts = Get-Date -Format "HH:mm:ss.fff"
    $p = Get-Process -Name FIFA17 -EA SilentlyContinue
    if ($p) {
        $conns = netstat -ano | Select-String $p.Id | Out-String
        $log += "=== $ts ===`n$conns`n"
    }
}

$serverOut = (Receive-Job $sj 2>&1 | Out-String).Trim()
Stop-Job $sj -EA SilentlyContinue; Remove-Job $sj -EA SilentlyContinue

# Get last 5000 chars of server output
$serverTail = if($serverOut.Length -gt 5000){$serverOut.Substring($serverOut.Length-5000)}else{$serverOut}
$log += "`n=== SERVER OUTPUT (last 5000 chars) ===`n$serverTail`n"
Set-Content $resultsFile $log -Encoding UTF8
Write-Host "Results saved to connection-monitor.log" -ForegroundColor Green

git add connection-monitor.log; git commit -m "Connection monitor results"; git push 2>&1
