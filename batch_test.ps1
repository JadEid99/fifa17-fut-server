# Batch v11: Test single-record TLS response (server change)
# Just one test - the server now sends all handshake messages in one TLS record
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS9 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KS9]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KS9]::Enter()} }
function FQ { if(Focus){[KS9]::Q()} }
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
    # T1: Single-record server + baseline patches + 20s wait
    @{ name="T01_single_record_baseline"; desc="Server sends all handshake in 1 TLS record + baseline patches"
       patch=$baseline; wait=20 },
    # T2: Single-record server + NO patches (test if single record alone fixes it)
    @{ name="T02_single_record_no_patches"; desc="Server sends all handshake in 1 TLS record, NO Frida patches"
       patch="send('no patches');"; wait=15 },
    # T3: Single-record server + baseline + hook recv to see if game reads our response
    @{ name="T03_single_record_hook_recv"; desc="Single record + baseline + hook recv()"
       patch=@"
$baseline
var ws2=Process.getModuleByName('ws2_32.dll');
var recvFn=ws2.getExportByName('recv');
Interceptor.attach(recvFn,{
  onEnter:function(args){this.buf=args[1];this.len=args[2].toInt32();this.sock=args[0];},
  onLeave:function(ret){
    var n=ret.toInt32();
    if(n>0){
      var first=this.buf.readU8();
      send('recv(sock='+this.sock+') got '+n+' bytes, first=0x'+first.toString(16));
    }
  }
});
"@; wait=15 }
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v11 ($timestamp) === $($patches.Count) tests`n" -Encoding UTF8
Write-Host "=== BATCH v11 - $($patches.Count) tests ===" -ForegroundColor Cyan

Kill-All
Launch-Game

$n=0
foreach($p in $patches){
    $n++; Write-Host "[$n/$($patches.Count)] $($p.name)" -ForegroundColor Yellow
    
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){
        Write-Host "  CRASHED - relaunching" -ForegroundColor Red
        Add-Content $resultsFile "[$n] $($p.name) | CRASHED | $($p.desc)`n"
        Kill-All; Launch-Game
    }
    
    # Restart server for clean output
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
    if($so -match "PLAINTEXT Blaze"){$r="PLAINTEXT_BLAZE"}
    if($so -match "Phase=.*received"){$r="RECEIVED_DATA"}
    if($so -match "Handshake type: 0x10"){$r="CLIENT_KEY_EXCHANGE"}
    if($so -match "GetServerInstance"){$r="BLAZE_REQUEST"}
    if($so -match "Encrypted Finished"){$r="TLS_COMPLETE"}
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

Kill-All
Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log;git commit -m "Batch v11 $timestamp";git push 2>&1
