# Batch v7: Target functions called from cert_process
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS5 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KS5]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KS5]::Enter()} }
function FQ { if(Focus){[KS5]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }

# cert_process (+0x6127020) calls:
#   +0x612E810 at +0x6127062
#   +0x612A560 at +0x6127071
#   +0x6138680 at +0x61270B5 and +0x612720A  <-- NEW, possibly RSA verify
#   +0x7714C70 at +0x612715A  <-- far call, possibly external
#
# cert_receive (+0x6127B40) calls:
#   +0x6127AA0 at +0x6127B64  <-- sub-function
#   +0x612E810 at +0x6127BF6
#   +0x612A560 at +0x6127C08
#   +0x612E770 at +0x6127C2E  <-- error handler
#
# cert_finalize (+0x61279F0) calls:
#   +0x612E770 at +0x6127A1B  <-- error handler
#   +0x612E180 at +0x6127A6A
#   +0x612E960 at +0x6127AB0
#   +0x612A560 at +0x6127ABB

$patches = @(
    # === Target +0x6138680 (called from cert_process, possibly RSA verify) ===
    @{ name="RSA_6138680_ret0"; desc="+0x6138680 ret 0"
       patch='Memory.protect(b.add(0x6138680),6,"rwx");b.add(0x6138680).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);'
       revert='var a=b.add(0x6138680);var o=[];for(var i=0;i<6;i++)o.push(a.add(i).readU8());send("orig:"+o.join(","));' },
    @{ name="RSA_6138680_ret1"; desc="+0x6138680 ret 1"
       patch='Memory.protect(b.add(0x6138680),6,"rwx");b.add(0x6138680).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);'
       revert='' },
    @{ name="NOP_call_61270B5"; desc="NOP CALL to +0x6138680 at +0x61270B5"
       patch='Memory.protect(b.add(0x61270B5),5,"rwx");b.add(0x61270B5).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61270B5),5,"rwx");b.add(0x61270B5).writeByteArray([0xE8,0xC6,0x15,0x01,0x00]);' },
    @{ name="NOP_call_612720A"; desc="NOP CALL to +0x6138680 at +0x612720A"
       patch='Memory.protect(b.add(0x612720A),5,"rwx");b.add(0x612720A).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x612720A),5,"rwx");b.add(0x612720A).writeByteArray([0xE8,0x71,0x14,0x01,0x00]);' },

    # === Target +0x6127AA0 (sub-function called from cert_receive) ===
    @{ name="fn_7AA0_ret0"; desc="+0x6127AA0 ret 0"
       patch='Memory.protect(b.add(0x6127AA0),6,"rwx");b.add(0x6127AA0).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);'
       revert='' },
    @{ name="fn_7AA0_ret1"; desc="+0x6127AA0 ret 1"
       patch='Memory.protect(b.add(0x6127AA0),6,"rwx");b.add(0x6127AA0).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);'
       revert='' },

    # === Target +0x612E180 and +0x612E960 (called from cert_finalize) ===
    @{ name="fn_E180_ret0"; desc="+0x612E180 ret 0"
       patch='Memory.protect(b.add(0x612E180),6,"rwx");b.add(0x612E180).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);'
       revert='' },
    @{ name="fn_E960_ret0"; desc="+0x612E960 ret 0"
       patch='Memory.protect(b.add(0x612E960),6,"rwx");b.add(0x612E960).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);'
       revert='' },

    # === Target +0x7714C70 (far call from cert_process) ===
    @{ name="fn_7714C70_ret0"; desc="+0x7714C70 ret 0"
       patch='Memory.protect(b.add(0x7714C70),6,"rwx");b.add(0x7714C70).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);'
       revert='' },

    # === COMBOS with NOP +644E (known to prevent disconnect) ===
    @{ name="RSA_ret0_NOP644E"; desc="+0x6138680 ret 0 + NOP error CALL +644E"
       patch='Memory.protect(b.add(0x6138680),6,"rwx");b.add(0x6138680).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='' },
    @{ name="fn7AA0_ret1_NOP644E"; desc="+0x6127AA0 ret 1 + NOP error CALL +644E"
       patch='Memory.protect(b.add(0x6127AA0),6,"rwx");b.add(0x6127AA0).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='' },
    @{ name="E180_E960_ret0_NOP644E"; desc="E180+E960 ret 0 + NOP +644E"
       patch='Memory.protect(b.add(0x612E180),6,"rwx");b.add(0x612E180).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);Memory.protect(b.add(0x612E960),6,"rwx");b.add(0x612E960).writeByteArray([0xB8,0x00,0x00,0x00,0x00,0xC3]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='' }
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v7 ($timestamp) === $($patches.Count) patches`n" -Encoding UTF8
Write-Host "=== BATCH v7 - $($patches.Count) patches ===" -ForegroundColor Cyan
Kill-All
$sj = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2; Launch-Game; Write-Host "Ready." -ForegroundColor Green

$n=0
foreach($p in $patches){
    $n++; Write-Host "[$n/$($patches.Count)] $($p.name)" -ForegroundColor Yellow
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){
        Write-Host "  CRASHED" -ForegroundColor Red
        Add-Content $resultsFile "[$n] $($p.name) | CRASHED | $($p.desc)`n"
        Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue;Kill-All
        $sj=Start-Job -ScriptBlock{param($r);node "$r\server-standalone\server.mjs" 2>&1} -ArgumentList $repoRoot
        Start-Sleep 2;Launch-Game
    }
    Receive-Job $sj 2>&1|Out-Null
    $fo=Run-Frida $p.patch; Start-Sleep 1; FQ; Start-Sleep 15
    $so=(Receive-Job $sj 2>&1|Out-String).Trim()
    $r="UNKNOWN"
    if($so -match "Phase=.*received"){$r="RECEIVED_DATA"}
    if($so -match "Record: type=0x16"){$r="TLS_HANDSHAKE"}
    if($so -match "Encrypted Finished"){$r="TLS_COMPLETE"}
    if($so -match "Decrypted"){$r="DECRYPTED"}
    if($so -match "ECONNRESET"){$r="ECONNRESET"}
    if($so -match "15 03 00 00 02 02"){$r="SSL_ALERT"}
    if($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "Disconnected"){$r="HANGING"}
    if($so -eq ""){$r="NO_CONNECTION"}
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){$r+="+CRASHED"}
    $color=switch -Regex($r){"RECEIVED|TLS_|DECRYPTED"{"Green"}"HANGING"{"Yellow"}default{"Red"}}
    Write-Host "  -> $r" -ForegroundColor $color
    $ss=if($so.Length -gt 300){$so.Substring($so.Length-300)}else{$so}
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nSERVER: $ss`n" -Encoding UTF8
    if($p.revert){Run-Frida $p.revert|Out-Null;Start-Sleep 1}
    FEnter;Start-Sleep 2
}
Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue
Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log;git commit -m "Batch v7 $timestamp";git push 2>&1
