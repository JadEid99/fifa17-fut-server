# Batch v12: Fresh game restart + hook ALL Winsock functions
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSA {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSA]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSA]::Enter()} }
function FQ { if(Focus){[KSA]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }

$baseline = @'
Memory.protect(b.add(0x612522d),1,"rwx");b.add(0x612522d).writeU8(0xEB);
Memory.protect(b.add(0x612753d),1,"rwx");b.add(0x612753d).writeU8(0xEB);
Memory.protect(b.add(0x6127c29),1,"rwx");b.add(0x6127c29).writeU8(0xEB);
Memory.protect(b.add(0x612644e),5,"rwx");b.add(0x612644e).writeByteArray([0x90,0x90,0x90,0x90,0x90]);
Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);
'@

$patches = @(
    # T1: FRESH game + baseline + hook ALL winsock read functions
    @{ name="T01_fresh_hook_all_winsock"; desc="FRESH game + baseline + hook recv/WSARecv/select"
       fresh=$true
       patch=@"
$baseline
var ws2=Process.getModuleByName('ws2_32.dll');
['recv','WSARecv','recvfrom','select','WSAWaitForMultipleEvents'].forEach(function(fn){
  try{
    var addr=ws2.getExportByName(fn);
    Interceptor.attach(addr,{
      onEnter:function(){this.fn=fn;},
      onLeave:function(ret){send(fn+'() returned '+ret.toInt32());}
    });
    send('Hooked '+fn);
  }catch(e){send('No '+fn);}
});
"@; wait=20 },

    # T2: FRESH game + NO patches + see if we get ECONNRESET (verify fresh state)
    @{ name="T02_fresh_no_patches_control"; desc="FRESH game, NO patches (should get ECONNRESET)"
       fresh=$true
       patch="send('no patches');"; wait=15 },

    # T3: FRESH game + baseline only (verify baseline still prevents disconnect)
    @{ name="T03_fresh_baseline_only"; desc="FRESH game + baseline patches"
       fresh=$true
       patch=$baseline; wait=20 }
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v12 ($timestamp) === $($patches.Count) tests`n" -Encoding UTF8
Write-Host "=== BATCH v12 - $($patches.Count) tests ===" -ForegroundColor Cyan

foreach($p in $patches){
    $n = [array]::IndexOf($patches, $p) + 1
    Write-Host "[$n/$($patches.Count)] $($p.name)" -ForegroundColor Yellow
    
    if($p.fresh){
        Write-Host "  Fresh game restart..." -ForegroundColor Gray
        Kill-All; Launch-Game
    }
    
    Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 1
    $sj=Start-Job -ScriptBlock{param($r);node "$r\server-standalone\server.mjs" 2>&1} -ArgumentList $repoRoot
    Start-Sleep 2
    
    $fo=Run-Frida $p.patch
    Start-Sleep 1; FQ
    
    $waitTime = if($p.wait){$p.wait}else{15}
    Start-Sleep $waitTime
    
    $so=(Receive-Job $sj 2>&1|Out-String).Trim()
    Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue
    
    $r="UNKNOWN"
    if($so -match "TIMEOUT: No data"){$r="TIMEOUT_NO_DATA"}
    if($so -match "Phase=.*received"){$r="RECEIVED_DATA"}
    if($so -match "Handshake type: 0x10"){$r="CLIENT_KEY_EXCHANGE"}
    if($so -match "ECONNRESET"){$r="ECONNRESET"}
    if($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "Disconnected" -and $so -notmatch "TIMEOUT"){$r="HANGING"}
    if($so -eq ""){$r="NO_CONNECTION"}
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){$r+="+CRASHED"}
    
    $color=switch -Regex($r){"CLIENT_KEY|TLS_COMPLETE|RECEIVED"{"Green"}"HANGING|TIMEOUT"{"Yellow"}default{"Red"}}
    Write-Host "  -> $r" -ForegroundColor $color
    
    $ss=if($so.Length -gt 500){$so.Substring($so.Length-500)}else{$so}
    $ff=if($fo -and $fo.Length -gt 500){$fo.Substring($fo.Length-500)}else{$fo}
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nFRIDA: $ff`nSERVER: $ss`n" -Encoding UTF8
    
    FEnter; Start-Sleep 2
}

Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log;git commit -m "Batch v12 $timestamp";git push 2>&1
