# Batch v8: Force ST_UNSECURE plaintext mode
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS6 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KS6]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KS6]::Enter()} }
function FQ { if(Focus){[KS6]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }

# From DirtySDK source:
# iState is at struct offset +0x8C
# ST_UNSECURE is the state where ProtoSSL uses raw sockets (no SSL)
# We need to find what value ST_UNSECURE is. From the source:
#   ST_ADDR = connecting
#   ST_CONN = connected, starting SSL
#   ST3_SEND_HELLO = sending ClientHello (state 1)
#   ST3_RECV_HELLO = receiving ServerHello (state 2)
#   etc.
#   ST3_SECURE = SSL established
#   ST_UNSECURE = plaintext mode
#   ST_FAIL* = various failure states
#
# From the code: state values we've seen:
#   3 = State 3 (cert processing)
#   4 = State 4 (ServerHelloDone)
#   6 = State 6 (ChangeCipherSpec)
#   7 = failure state
#
# ST_UNSECURE is likely a small positive number or 0.
# From the source enum order, it's probably around 0x10-0x20 range.
# But we also saw the code check: if (pState->iState == ST_UNSECURE)
# Let's try different values.
#
# Actually, from the source code structure:
# The states are defined as sequential integers.
# Looking at the code flow: ST_UNSECURE is checked in ProtoSSLSend
# alongside ST3_SECURE. ST3_SECURE is the final SSL state.
# The state machine goes: 1,2,3,4,5,6,7 for SSL states.
# ST_UNSECURE is probably a separate value like -1 or a high number.
#
# Let's search for the ProtoSSLSend function and see what value it checks.

$patches = @(
    # === DIAGNOSTIC: Dump ProtoSSLSend to find ST_UNSECURE value ===
    # ProtoSSLSend checks iState == ST3_SECURE and iState == ST_UNSECURE
    # We need to find this function. It's called from higher-level code.
    # Search for the pattern: CMP [reg+0x8C], value ... SocketSend
    @{ name="DUMP_state_machine_start"; desc="Dump 256 bytes at SSL state machine start +0x6126213"
       patch=@'
var a=b.add(0x6126200);
for(var r=0;r<8;r++){
  var h="";var o=r*32;
  for(var i=0;i<32;i++) h+=("0"+a.add(o+i).readU8().toString(16)).slice(-2)+" ";
  send("SM +"+(0x6126200+o).toString(16)+": "+h);
}
'@
       revert='' },

    # === PATCHES: Set iState to various values after NOP-ing error CALL ===
    # We know NOP +644E prevents disconnect. Now also set iState.
    # iState is at [rbx+0x8C]. In the state machine, rbx = struct pointer.
    # After NOP-ing the error call, we can write to [rbx+0x8C] directly.
    # But we don't have rbx in Frida... we need to find the struct.
    #
    # Alternative: patch the state machine to SET iState after the error path.
    # At +0x6126453 (after the NOP'd call), the original code sets error state.
    # We can replace it with code that sets a different state.
    #
    # Original at +0x6126453: 66 C7 83 1F 0C 00 00 00 01
    #   = MOV WORD [rbx+0xC1F], 0x0100
    # We can change this to: C7 83 8C 00 00 00 XX 00 00 00
    #   = MOV DWORD [rbx+0x8C], XX (set iState to XX)
    # This is 10 bytes, we have 14 bytes available (9+7 from the two writes)

    # Try setting iState to 0 (might be ST_UNSECURE or ST_IDLE)
    @{ name="SET_state_0_NOP644E"; desc="NOP error CALL + set iState=0"
       patch='Memory.protect(b.add(0x612644E),21,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0xC7,0x83,0x8C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='' },

    # Try iState = 8 (might be ST3_SECURE or close to it)
    @{ name="SET_state_8_NOP644E"; desc="NOP error CALL + set iState=8"
       patch='Memory.protect(b.add(0x612644E),21,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0xC7,0x83,0x8C,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='' },

    # Try iState = 9
    @{ name="SET_state_9_NOP644E"; desc="NOP error CALL + set iState=9"
       patch='Memory.protect(b.add(0x612644E),21,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0xC7,0x83,0x8C,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='' },

    # Try iState = 10
    @{ name="SET_state_10_NOP644E"; desc="NOP error CALL + set iState=10"
       patch='Memory.protect(b.add(0x612644E),21,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0xC7,0x83,0x8C,0x00,0x00,0x00,0x0A,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='' },

    # Try iState = -1 (0xFFFFFFFF)
    @{ name="SET_state_neg1_NOP644E"; desc="NOP error CALL + set iState=-1"
       patch='Memory.protect(b.add(0x612644E),21,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0xC7,0x83,0x8C,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='' },

    # === DIAGNOSTIC: Find ProtoSSLSend by searching for SocketSend pattern ===
    # ProtoSSLSend calls SocketSend when in ST_UNSECURE mode.
    # SocketSend is a Winsock wrapper. Let's search for code that checks
    # [reg+0x8C] and then calls send().
    @{ name="DUMP_around_state_checks"; desc="Dump code that checks iState for send/recv"
       patch=@'
// Search for CMP DWORD [rbx+0x8C] pattern in the SSL code region
var start = b.add(0x6120000);
var found = 0;
for (var i = 0; i < 0x20000 && found < 20; i++) {
    // Pattern: 83 BB 8C 00 00 00 XX (CMP DWORD [rbx+0x8C], XX)
    if (start.add(i).readU8() === 0x83 && start.add(i+1).readU8() === 0xBB &&
        start.add(i+2).readU8() === 0x8C && start.add(i+3).readU8() === 0x00 &&
        start.add(i+4).readU8() === 0x00 && start.add(i+5).readU8() === 0x00) {
        var val = start.add(i+6).readU8();
        send("CMP [rbx+0x8C],"+val+" at +"+(0x6120000+i).toString(16));
        found++;
    }
    // Also: 39 BB 8C 00 00 00 (CMP [rbx+0x8C], edi/etc)
    if (start.add(i).readU8() === 0x39 && start.add(i+2).readU8() === 0x8C &&
        start.add(i+3).readU8() === 0x00 && start.add(i+4).readU8() === 0x00 &&
        start.add(i+5).readU8() === 0x00) {
        send("CMP [rbx+0x8C],reg at +"+(0x6120000+i).toString(16));
        found++;
    }
}
send("Found "+found+" state checks");
'@
       revert='' },

    # === Try setting iState to values found in the state check dump ===
    # These will be filled based on diagnostic results, but let's try common ones
    @{ name="SET_state_5_NOP644E"; desc="NOP error CALL + set iState=5"
       patch='Memory.protect(b.add(0x612644E),21,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0xC7,0x83,0x8C,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='' },

    @{ name="SET_state_6_NOP644E"; desc="NOP error CALL + set iState=6"
       patch='Memory.protect(b.add(0x612644E),21,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0xC7,0x83,0x8C,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='' }
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v8 ($timestamp) === $($patches.Count) patches`n" -Encoding UTF8
Write-Host "=== BATCH v8 - $($patches.Count) patches ===" -ForegroundColor Cyan
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
    if($so -match "PLAINTEXT Blaze"){$r="PLAINTEXT_BLAZE"}
    if($so -match "Phase=.*received"){$r="RECEIVED_DATA"}
    if($so -match "Record: type=0x16"){$r="TLS_HANDSHAKE"}
    if($so -match "GetServerInstance"){$r="BLAZE_REQUEST"}
    if($so -match "Encrypted Finished"){$r="TLS_COMPLETE"}
    if($so -match "Decrypted"){$r="DECRYPTED"}
    if($so -match "ECONNRESET"){$r="ECONNRESET"}
    if($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "Disconnected"){$r="HANGING"}
    if($so -eq ""){$r="NO_CONNECTION"}
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){$r+="+CRASHED"}
    $color=switch -Regex($r){"PLAINTEXT|BLAZE_REQUEST|RECEIVED|TLS_COMPLETE|DECRYPTED"{"Green"}"HANGING"{"Yellow"}default{"Red"}}
    Write-Host "  -> $r" -ForegroundColor $color
    $ss=if($so.Length -gt 400){$so.Substring($so.Length-400)}else{$so}
    $ff=if($fo -and $fo.Length -gt 400){$fo.Substring($fo.Length-400)}else{$fo}
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nFRIDA: $ff`nSERVER: $ss`n" -Encoding UTF8
    FEnter;Start-Sleep 2
}
Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue
Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log;git commit -m "Batch v8 $timestamp";git push 2>&1
