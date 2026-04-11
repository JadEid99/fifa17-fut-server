# FIFA 17 SSL Bypass - Batch v6: Target bAllowAnyCert in cert_receive
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS4 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KS4]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KS4]::Enter()} }
function FQ { if(Focus){[KS4]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }

# From cert_receive dump at +0x6127B40:
# +0x6127C20: 75 53           JNE +0x53 (skip error if bAllowAnyCert != 0)
# +0x6127C22: 80 BB 20 0C 00 00 00  CMP BYTE [rbx+0xC20], 0
# Wait - let me re-read. The dump shows:
# +6127C20: 75 53 80 bb 20 0c 00 00 00 75 18 48 8b 0b e8 3d 6b 00 00 66 c7 83 1f 0c 00 00 00 01 c6 83 21 0c
# So:
# +7C20: 75 53 = JNE +0x53 (some earlier condition)
# +7C22: 80 BB 20 0C 00 00 00 = CMP BYTE [rbx+0xC20], 0
# +7C29: 75 18 = JNE +0x18 (if bAllowAnyCert != 0, skip error)
# +7C2B: 48 8B 0B = MOV rcx, [rbx]
# +7C2E: E8 3D 6B 00 00 = CALL +0x612E770 (error handler!)
# +7C33: 66 C7 83 1F 0C 00 00 00 01 = MOV WORD [rbx+0xC1F], 0x0100 (set error state)
# +7C3C: C6 83 21 0C ... = MOV BYTE [rbx+0xC21], ...
#
# So the bAllowAnyCert check is:
#   CMP BYTE [rbx+0xC20], 0
#   JNE skip_error  (if bAllowAnyCert != 0, skip)
#   CALL error_handler
#   set error state
#
# To bypass: either NOP the CMP+JNE or change JNE to JMP

$patches = @(
    # === A: Patch bAllowAnyCert check in cert_receive ===
    @{ name="A1_JNE_to_JMP_7C29"; desc="Change JNE to JMP at +0x6127C29 (always skip cert error)"
       patch='Memory.protect(b.add(0x6127C29),1,"rwx");b.add(0x6127C29).writeU8(0xEB);'
       revert='Memory.protect(b.add(0x6127C29),1,"rwx");b.add(0x6127C29).writeU8(0x75);' },
    @{ name="A2_NOP_CMP_JNE_7C22"; desc="NOP the CMP+JNE at +0x6127C22 (9 bytes)"
       patch='Memory.protect(b.add(0x6127C22),9,"rwx");b.add(0x6127C22).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C22),9,"rwx");b.add(0x6127C22).writeByteArray([0x80,0xBB,0x20,0x0C,0x00,0x00,0x00,0x75,0x18]);' },
    @{ name="A3_NOP_error_call_7C2E"; desc="NOP the error handler CALL at +0x6127C2E"
       patch='Memory.protect(b.add(0x6127C2E),5,"rwx");b.add(0x6127C2E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C2E),5,"rwx");b.add(0x6127C2E).writeByteArray([0xE8,0x3D,0x6B,0x00,0x00]);' },
    @{ name="A4_NOP_error_call_AND_state_7C2E"; desc="NOP error CALL + error state writes at +0x6127C2E"
       patch='Memory.protect(b.add(0x6127C2E),14,"rwx");b.add(0x6127C2E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C2E),14,"rwx");b.add(0x6127C2E).writeByteArray([0xE8,0x3D,0x6B,0x00,0x00,0x66,0xC7,0x83,0x1F,0x0C,0x00,0x00,0x00,0x01]);' },

    # === B: Same patches + also NOP the State 5 error CALL ===
    @{ name="B1_JMP_7C29_AND_NOP_644E"; desc="JMP at +7C29 AND NOP error CALL at +644E"
       patch='Memory.protect(b.add(0x6127C29),1,"rwx");b.add(0x6127C29).writeU8(0xEB);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C29),1,"rwx");b.add(0x6127C29).writeU8(0x75);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' },
    @{ name="B2_NOP_CMP_7C22_AND_NOP_644E"; desc="NOP CMP+JNE at +7C22 AND NOP error CALL at +644E"
       patch='Memory.protect(b.add(0x6127C22),9,"rwx");b.add(0x6127C22).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C22),9,"rwx");b.add(0x6127C22).writeByteArray([0x80,0xBB,0x20,0x0C,0x00,0x00,0x00,0x75,0x18]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' },
    @{ name="B3_NOP_all_error_calls"; desc="NOP error CALL at +7C2E AND +644E AND state writes"
       patch='Memory.protect(b.add(0x6127C2E),14,"rwx");b.add(0x6127C2E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x6126453),14,"rwx");b.add(0x6126453).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C2E),14,"rwx");b.add(0x6127C2E).writeByteArray([0xE8,0x3D,0x6B,0x00,0x00,0x66,0xC7,0x83,0x1F,0x0C,0x00,0x00,0x00,0x01]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);Memory.protect(b.add(0x6126453),14,"rwx");b.add(0x6126453).writeByteArray([0x66,0xC7,0x83,0x1F,0x0C,0x00,0x00,0x00,0x01,0x40,0x88,0xBB,0x21,0x0C]);' },

    # === C: Also patch the first JNE at +7C20 ===
    @{ name="C1_NOP_both_JNE_7C20_7C29"; desc="NOP JNE at +7C20 AND +7C29"
       patch='Memory.protect(b.add(0x6127C20),2,"rwx");b.add(0x6127C20).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x6127C29),2,"rwx");b.add(0x6127C29).writeByteArray([0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C20),2,"rwx");b.add(0x6127C20).writeByteArray([0x75,0x53]);Memory.protect(b.add(0x6127C29),2,"rwx");b.add(0x6127C29).writeByteArray([0x75,0x18]);' },
    @{ name="C2_JMP_7C20_AND_NOP_644E"; desc="JMP at +7C20 AND NOP error CALL at +644E"
       patch='Memory.protect(b.add(0x6127C20),1,"rwx");b.add(0x6127C20).writeU8(0xEB);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127C20),1,"rwx");b.add(0x6127C20).writeU8(0x75);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' },

    # === D: Patch cert_finalize error handler call ===
    # cert_finalize calls +0x612E770 at +0x6127A1B
    @{ name="D1_NOP_finalize_error_7A1B"; desc="NOP error CALL in cert_finalize at +7A1B"
       patch='Memory.protect(b.add(0x6127A1B),5,"rwx");b.add(0x6127A1B).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127A1B),5,"rwx");b.add(0x6127A1B).writeByteArray([0xE8,0x50,0x6D,0x00,0x00]);' },
    @{ name="D2_NOP_finalize_AND_receive_errors"; desc="NOP error CALLs in both cert_finalize and cert_receive"
       patch='Memory.protect(b.add(0x6127A1B),5,"rwx");b.add(0x6127A1B).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x6127C2E),5,"rwx");b.add(0x6127C2E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127A1B),5,"rwx");b.add(0x6127A1B).writeByteArray([0xE8,0x50,0x6D,0x00,0x00]);Memory.protect(b.add(0x6127C2E),5,"rwx");b.add(0x6127C2E).writeByteArray([0xE8,0x3D,0x6B,0x00,0x00]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' }
)

# Main loop
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v6 ($timestamp) === $($patches.Count) patches`n" -Encoding UTF8
Write-Host "=== BATCH v6 - $($patches.Count) patches ===" -ForegroundColor Cyan
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
git add batch-results.log;git commit -m "Batch v6 $timestamp";git push 2>&1
