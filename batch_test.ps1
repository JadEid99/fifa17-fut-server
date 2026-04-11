# FIFA 17 SSL Bypass - Batch v5: Deep dive into cert_process internals
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS3 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KS3]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KS3]::Enter()} }
function FQ { if(Focus){[KS3]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }


# cert_process at +0x6127020 calls:
#   +0x612E810 (at offset +0x42 inside cert_process)
#   +0x612A560 (at offset +0x51 inside cert_process)
# We need to dump MORE of cert_process to find all internal calls,
# especially the cert verification call.

$patches = @(
    # === DIAGNOSTIC: Dump 512 bytes of cert_process ===
    @{ name="DUMP_cert_process_512"; desc="Dump 512 bytes of cert_process"
       patch=@'
var a=b.add(0x6127020);
for(var r=0;r<16;r++){
  var h="";var o=r*32;
  for(var i=0;i<32;i++) h+=("0"+a.add(o+i).readU8().toString(16)).slice(-2)+" ";
  send("CP +"+(0x6127020+o).toString(16)+": "+h);
}
for(var i=0;i<512;i++){
  if(a.add(i).readU8()===0xE8){
    var d=a.add(i+1).readS32();
    send("CALL +"+(0x6127020+i).toString(16)+" -> +"+(0x6127020+i+5+d).toString(16));
  }
}
'@
       revert='' },

    # === DIAGNOSTIC: Dump cert_receive (+0x6127B40) ===
    @{ name="DUMP_cert_receive_256"; desc="Dump 256 bytes of cert_receive"
       patch=@'
var a=b.add(0x6127B40);
for(var r=0;r<8;r++){
  var h="";var o=r*32;
  for(var i=0;i<32;i++) h+=("0"+a.add(o+i).readU8().toString(16)).slice(-2)+" ";
  send("CR +"+(0x6127B40+o).toString(16)+": "+h);
}
for(var i=0;i<256;i++){
  if(a.add(i).readU8()===0xE8){
    var d=a.add(i+1).readS32();
    send("CALL +"+(0x6127B40+i).toString(16)+" -> +"+(0x6127B40+i+5+d).toString(16));
  }
}
'@
       revert='' },

    # === DIAGNOSTIC: Dump cert_finalize (+0x61279F0) ===
    @{ name="DUMP_cert_finalize_256"; desc="Dump 256 bytes of cert_finalize"
       patch=@'
var a=b.add(0x61279F0);
for(var r=0;r<8;r++){
  var h="";var o=r*32;
  for(var i=0;i<32;i++) h+=("0"+a.add(o+i).readU8().toString(16)).slice(-2)+" ";
  send("CF +"+(0x61279F0+o).toString(16)+": "+h);
}
for(var i=0;i<256;i++){
  if(a.add(i).readU8()===0xE8){
    var d=a.add(i+1).readS32();
    send("CALL +"+(0x61279F0+i).toString(16)+" -> +"+(0x61279F0+i+5+d).toString(16));
  }
}
'@
       revert='' },

    # === DIAGNOSTIC: Dump function at +0x612E810 (called from cert_process) ===
    @{ name="DUMP_fn_E810_256"; desc="Dump 256 bytes of +0x612E810"
       patch=@'
var a=b.add(0x612E810);
for(var r=0;r<8;r++){
  var h="";var o=r*32;
  for(var i=0;i<32;i++) h+=("0"+a.add(o+i).readU8().toString(16)).slice(-2)+" ";
  send("E810 +"+(0x612E810+o).toString(16)+": "+h);
}
for(var i=0;i<256;i++){
  if(a.add(i).readU8()===0xE8){
    var d=a.add(i+1).readS32();
    send("CALL +"+(0x612E810+i).toString(16)+" -> +"+(0x612E810+i+5+d).toString(16));
  }
}
'@
       revert='' },

    # === PATCHES: Target internal calls within cert_process ===
    # cert_process calls E810 at +0x6127062 and A560 at +0x6127071
    @{ name="P_NOP_E810_call"; desc="NOP CALL to E810 inside cert_process"
       patch='Memory.protect(b.add(0x6127062),5,"rwx");b.add(0x6127062).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127062),5,"rwx");b.add(0x6127062).writeByteArray([0xE8,0xA9,0x77,0x00,0x00]);' },
    @{ name="P_NOP_A560_call"; desc="NOP CALL to A560 inside cert_process"
       patch='Memory.protect(b.add(0x6127071),5,"rwx");b.add(0x6127071).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127071),5,"rwx");b.add(0x6127071).writeByteArray([0xE8,0xEA,0x34,0x00,0x00]);' },
    @{ name="P_E810_ret0"; desc="Make +0x612E810 return 0"
       patch='Memory.protect(b.add(0x612E810),3,"rwx");b.add(0x612E810).writeByteArray([0x31,0xC0,0xC3]);'
       revert='Memory.protect(b.add(0x612E810),3,"rwx");b.add(0x612E810).writeByteArray([0x48,0x89,0x5C]);' },
    @{ name="P_A560_ret0"; desc="Make +0x612A560 return 0"
       patch='Memory.protect(b.add(0x612A560),3,"rwx");b.add(0x612A560).writeByteArray([0x31,0xC0,0xC3]);'
       revert='Memory.protect(b.add(0x612A560),3,"rwx");b.add(0x612A560).writeByteArray([0x48,0x89,0x5C]);' },
    @{ name="P_A560_ret1"; desc="Make +0x612A560 return 1"
       patch='Memory.protect(b.add(0x612A560),6,"rwx");b.add(0x612A560).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);'
       revert='Memory.protect(b.add(0x612A560),6,"rwx");b.add(0x612A560).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);' },

    # === COMBO: NOP JLE in State3 + NOP error CALL in State5 + various ===
    @{ name="C_NOP_JLE_NOP644E_E810ret0"; desc="NOP JLE + NOP error CALL + E810 ret 0"
       patch='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612E810),3,"rwx");b.add(0x612E810).writeByteArray([0x31,0xC0,0xC3]);'
       revert='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x7E,0x36]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);Memory.protect(b.add(0x612E810),3,"rwx");b.add(0x612E810).writeByteArray([0x48,0x89,0x5C]);' },
    @{ name="C_NOP_JLE_NOP644E_A560ret0"; desc="NOP JLE + NOP error CALL + A560 ret 0"
       patch='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612A560),3,"rwx");b.add(0x612A560).writeByteArray([0x31,0xC0,0xC3]);'
       revert='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x7E,0x36]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);Memory.protect(b.add(0x612A560),3,"rwx");b.add(0x612A560).writeByteArray([0x48,0x89,0x5C]);' },
    @{ name="C_NOP_JLE_NOP644E_A560ret1"; desc="NOP JLE + NOP error CALL + A560 ret 1"
       patch='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612A560),6,"rwx");b.add(0x612A560).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);'
       revert='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x7E,0x36]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);Memory.protect(b.add(0x612A560),6,"rwx");b.add(0x612A560).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);' }
)


# Main loop
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v5 ($timestamp) === $($patches.Count) patches`n" -Encoding UTF8
Write-Host "=== BATCH v5 - $($patches.Count) patches ===" -ForegroundColor Cyan
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
    $fo=Run-Frida $p.patch; Start-Sleep 1; FQ; Start-Sleep 12
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
    # For diagnostic dumps, include frida output
    $ff=if($fo.Length -gt 500){$fo.Substring($fo.Length-500)}else{$fo}
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nFRIDA: $ff`nSERVER: $ss`n" -Encoding UTF8
    if($p.revert){Run-Frida $p.revert|Out-Null;Start-Sleep 1}
    FEnter;Start-Sleep 2
}
Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue
Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log;git commit -m "Batch v5 $timestamp";git push 2>&1
