# Batch v10: Diagnostic + new approaches
# Game stays running between tests (restart only on crash)
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS8 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KS8]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KS8]::Enter()} }
function FQ { if(Focus){[KS8]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }

$baseline = @'
Memory.protect(b.add(0x612522d),1,"rwx");b.add(0x612522d).writeU8(0xEB);
Memory.protect(b.add(0x612753d),1,"rwx");b.add(0x612753d).writeU8(0xEB);
Memory.protect(b.add(0x6127c29),1,"rwx");b.add(0x6127c29).writeU8(0xEB);
Memory.protect(b.add(0x612644e),5,"rwx");b.add(0x612644e).writeByteArray([0x90,0x90,0x90,0x90,0x90]);
Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);
'@

$patches = @(
    # T1: Baseline with 15s wait + timeout diagnostic (server has 10s timeout logging)
    @{ name="T01_baseline_15s_wait"; desc="baseline (5 patches), wait 15s for timeout diagnostic"
       patch=$baseline; wait=20 },

    # T2: Baseline + hook send() to see if game sends ANY data on the socket
    @{ name="T02_hook_send"; desc="baseline + hook Winsock send() to log all outgoing data"
       patch=@"
$baseline
var ws2=Process.getModuleByName('ws2_32.dll');
var sendFn=ws2.getExportByName('send');
Interceptor.attach(sendFn,{onEnter:function(args){
  var len=args[2].toInt32();
  if(len>0&&len<2000){
    var b0=args[1].readU8();
    send('send() len='+len+' first_byte=0x'+b0.toString(16));
  }
}});
"@; wait=15 },

    # T3: Baseline + hook recv() to see if game tries to read
    @{ name="T03_hook_recv"; desc="baseline + hook Winsock recv() to log all incoming reads"
       patch=@"
$baseline
var ws2=Process.getModuleByName('ws2_32.dll');
var recvFn=ws2.getExportByName('recv');
Interceptor.attach(recvFn,{
  onEnter:function(args){this.buf=args[1];this.len=args[2].toInt32();},
  onLeave:function(ret){
    var n=ret.toInt32();
    if(n>0){send('recv() got '+n+' bytes, first=0x'+this.buf.readU8().toString(16));}
    else{send('recv() returned '+n);}
  }
});
"@; wait=15 },

    # T4: Baseline + dump iState after connection to see what state the game is in
    @{ name="T04_dump_iState"; desc="baseline + dump iState from struct after connection"
       patch=@"
$baseline
// Wait 5 seconds then check iState
setTimeout(function(){
  var pattern='77 69 6E 74 65 72 31 35 2E 67 6F 73 72 65 64 69 72 65 63 74 6F 72 2E 65 61 2E 63 6F 6D';
  Process.enumerateRanges('rw-').forEach(function(range){
    if(range.size<0x200)return;
    try{
      Memory.scanSync(range.base,range.size,pattern).forEach(function(match){
        var strHost=match.address;
        try{if(strHost.add(0x100).readU16()!==2)return;}catch(e){return;}
        // Read iState candidates
        [-232,-196,-160,-124,-116].forEach(function(off){
          try{var v=strHost.add(off).readU32();send('strHost'+off+'='+v);}catch(e){}
        });
        // Also read bytes at +0x8C from various struct base guesses
        [-0x74,-0x7C,-0x84,-0x108].forEach(function(off){
          try{var v=strHost.add(off).readU32();send('strHost'+off+' (0x'+(-off).toString(16)+')='+v);}catch(e){}
        });
      });
    }catch(e){}
  });
},5000);
"@; wait=15 },

    # T5: No patches at all (control - should get ECONNRESET)
    @{ name="T05_no_patches"; desc="NO patches (control test)"
       patch="send('no patches applied');"; wait=15 }
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v10 ($timestamp) === $($patches.Count) tests`n" -Encoding UTF8
Write-Host "=== BATCH v10 - $($patches.Count) tests ===" -ForegroundColor Cyan

# Launch game once
Kill-All
$sj = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2; Launch-Game; Write-Host "Ready." -ForegroundColor Green

$n=0
foreach($p in $patches){
    $n++; Write-Host "[$n/$($patches.Count)] $($p.name)" -ForegroundColor Yellow
    
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){
        Write-Host "  CRASHED - relaunching" -ForegroundColor Red
        Add-Content $resultsFile "[$n] $($p.name) | CRASHED | $($p.desc)`n"
        Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue;Kill-All
        $sj=Start-Job -ScriptBlock{param($r);node "$r\server-standalone\server.mjs" 2>&1} -ArgumentList $repoRoot
        Start-Sleep 2;Launch-Game
    }
    
    # Restart server between tests to get clean output
    Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue
    Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 1
    $sj=Start-Job -ScriptBlock{param($r);node "$r\server-standalone\server.mjs" 2>&1} -ArgumentList $repoRoot
    Start-Sleep 2
    
    $fo=Run-Frida $p.patch
    Start-Sleep 1; FQ
    
    $waitTime = if($p.wait){$p.wait}else{15}
    Start-Sleep $waitTime
    
    $so=(Receive-Job $sj 2>&1|Out-String).Trim()
    
    $r="UNKNOWN"
    if($so -match "TIMEOUT: No data"){$r="TIMEOUT_NO_DATA"}
    if($so -match "PLAINTEXT Blaze"){$r="PLAINTEXT_BLAZE"}
    if($so -match "Phase=.*received"){$r="RECEIVED_DATA"}
    if($so -match "Record: type=0x16"){$r="TLS_HANDSHAKE"}
    if($so -match "GetServerInstance"){$r="BLAZE_REQUEST"}
    if($so -match "ClientKeyExchange"){$r="CLIENT_KEY_EXCHANGE"}
    if($so -match "ECONNRESET"){$r="ECONNRESET"}
    if($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "Disconnected" -and $so -notmatch "TIMEOUT"){$r="HANGING"}
    if($so -eq ""){$r="NO_CONNECTION"}
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){$r+="+CRASHED"}
    
    $color=switch -Regex($r){"PLAINTEXT|BLAZE|CLIENT_KEY|TLS_COMPLETE|DECRYPTED|RECEIVED"{"Green"}"HANGING|TIMEOUT"{"Yellow"}default{"Red"}}
    Write-Host "  -> $r" -ForegroundColor $color
    
    $ss=if($so.Length -gt 500){$so.Substring($so.Length-500)}else{$so}
    $ff=if($fo -and $fo.Length -gt 300){$fo.Substring($fo.Length-300)}else{$fo}
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nFRIDA: $ff`nSERVER: $ss`n" -Encoding UTF8
    
    FEnter; Start-Sleep 2
}

Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue
Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log;git commit -m "Batch v10 $timestamp";git push 2>&1
