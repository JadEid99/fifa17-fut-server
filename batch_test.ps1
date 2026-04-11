# Batch v9: All patches include the 3 bAllowAnyCert + error CALL NOP as baseline
# Then vary how we force the cert_process success path
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS7 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KS7]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KS7]::Enter()} }
function FQ { if(Focus){[KS7]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }

# BASELINE that goes into every patch:
# 3x bAllowAnyCert JNE->JMP + 1x NOP error CALL
$baseline = @'
Memory.protect(b.add(0x612522d),1,"rwx");b.add(0x612522d).writeU8(0xEB);
Memory.protect(b.add(0x612753d),1,"rwx");b.add(0x612753d).writeU8(0xEB);
Memory.protect(b.add(0x6127c29),1,"rwx");b.add(0x6127c29).writeU8(0xEB);
Memory.protect(b.add(0x612644e),5,"rwx");b.add(0x612644e).writeByteArray([0x90,0x90,0x90,0x90,0x90]);
'@

$patches = @(
    # Force eax=1 at cert_process result check
    @{ name="V01_xor_inc_eax"; desc="baseline + xor eax,eax; inc eax at +0x61262F5"
       patch="$baseline`nMemory.protect(b.add(0x61262F5),4,'rwx');b.add(0x61262F5).writeByteArray([0x31,0xC0,0xFF,0xC0]);" },
    # NOP the JLE only
    @{ name="V02_NOP_JLE"; desc="baseline + NOP JLE at +0x61262F7"
       patch="$baseline`nMemory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);" },
    # Force eax=0x40 (64) - cert_process might return byte count
    @{ name="V03_mov_eax_64"; desc="baseline + mov eax,0x40 at +0x61262F5"
       patch="$baseline`nMemory.protect(b.add(0x61262F5),4,'rwx');b.add(0x61262F5).writeByteArray([0xB0,0x40,0x90,0x90]);" },
    # NOP the cert_finalize call at +0x6126334 (it might reset state)
    @{ name="V04_NOP_finalize"; desc="baseline + NOP JLE + NOP cert_finalize CALL at +0x6126334"
       patch="$baseline`nMemory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x6126334),5,'rwx');b.add(0x6126334).writeByteArray([0x90,0x90,0x90,0x90,0x90]);" },
    # NOP the success function call at +0x6126311 (maybe it's crashing)
    @{ name="V05_NOP_success_fn"; desc="baseline + NOP JLE + NOP success fn CALL at +0x6126311"
       patch="$baseline`nMemory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x6126311),5,'rwx');b.add(0x6126311).writeByteArray([0x90,0x90,0x90,0x90,0x90]);" },
    # Skip entire State 3 - just set state=4 directly
    @{ name="V06_skip_state3"; desc="baseline + at State 3 check, set state=4 and skip"
       patch="$baseline`nMemory.protect(b.add(0x61262E3),5,'rwx');b.add(0x61262E3).writeByteArray([0xC7,0x83,0x8C,0x00,0x00]);Memory.protect(b.add(0x61262E8),8,'rwx');b.add(0x61262E8).writeByteArray([0x00,0x04,0x00,0x00,0x00,0xEB,0x62,0x90]);" },
    # NOP cert_receive call but keep cert_process
    @{ name="V07_NOP_cert_receive"; desc="baseline + NOP JLE + NOP cert_receive CALL at +0x61262E8"
       patch="$baseline`nMemory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x61262E8),5,'rwx');b.add(0x61262E8).writeByteArray([0x90,0x90,0x90,0x90,0x90]);" },
    # NOP cert_process call but keep cert_receive
    @{ name="V08_NOP_cert_process"; desc="baseline + NOP JLE + NOP cert_process CALL at +0x61262F0"
       patch="$baseline`nMemory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x61262F0),5,'rwx');b.add(0x61262F0).writeByteArray([0x90,0x90,0x90,0x90,0x90]);" },
    # NOP both cert_receive AND cert_process, force state=4
    @{ name="V09_NOP_both_calls"; desc="baseline + NOP JLE + NOP both cert calls"
       patch="$baseline`nMemory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x61262E8),5,'rwx');b.add(0x61262E8).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x61262F0),5,'rwx');b.add(0x61262F0).writeByteArray([0x90,0x90,0x90,0x90,0x90]);" },
    # Make cert_process return 1 + NOP JLE
    @{ name="V10_cert_process_ret1_NOP_JLE"; desc="baseline + cert_process ret 1 + NOP JLE"
       patch="$baseline`nMemory.protect(b.add(0x6127020),6,'rwx');b.add(0x6127020).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);Memory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);" },
    # Baseline only (control test)
    @{ name="V11_baseline_only"; desc="baseline only (3x bAllowAnyCert + NOP error CALL)"
       patch="$baseline" },
    # Everything: baseline + NOP JLE + NOP finalize + NOP success fn
    @{ name="V12_everything"; desc="baseline + NOP JLE + NOP finalize + NOP success fn + NOP cert_finalize error"
       patch="$baseline`nMemory.protect(b.add(0x61262F7),2,'rwx');b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x6126334),5,'rwx');b.add(0x6126334).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x6126311),5,'rwx');b.add(0x6126311).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x6127a1b),5,'rwx');b.add(0x6127a1b).writeByteArray([0x90,0x90,0x90,0x90,0x90]);" }
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v9 ($timestamp) === $($patches.Count) patches (all include baseline)`n" -Encoding UTF8
Write-Host "=== BATCH v9 - $($patches.Count) patches ===" -ForegroundColor Cyan

# Each test needs a fresh game since patches can't be cleanly reverted
foreach ($p in $patches) {
    $n = [array]::IndexOf($patches, $p) + 1
    Write-Host "`n[$n/$($patches.Count)] $($p.name)" -ForegroundColor Yellow
    
    Kill-All
    $sj = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
    Start-Sleep 2
    Launch-Game
    
    Receive-Job $sj 2>&1 | Out-Null
    $fo = Run-Frida $p.patch
    Start-Sleep 1
    FQ
    Start-Sleep 15
    
    $so = (Receive-Job $sj 2>&1 | Out-String).Trim()
    
    $r = "UNKNOWN"
    if ($so -match "PLAINTEXT Blaze") { $r = "PLAINTEXT_BLAZE" }
    if ($so -match "Phase=.*received") { $r = "RECEIVED_DATA" }
    if ($so -match "Record: type=0x16") { $r = "TLS_HANDSHAKE" }
    if ($so -match "GetServerInstance") { $r = "BLAZE_REQUEST" }
    if ($so -match "ClientKeyExchange") { $r = "CLIENT_KEY_EXCHANGE" }
    if ($so -match "Encrypted Finished") { $r = "TLS_COMPLETE" }
    if ($so -match "Decrypted") { $r = "DECRYPTED" }
    if ($so -match "ECONNRESET") { $r = "ECONNRESET" }
    if ($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "Disconnected") { $r = "HANGING" }
    if ($so -eq "") { $r = "NO_CONNECTION" }
    if (-not (Get-Process -Name FIFA17 -EA SilentlyContinue)) { $r += "+CRASHED" }
    
    $color = switch -Regex ($r) { "PLAINTEXT|BLAZE|CLIENT_KEY|TLS_COMPLETE|DECRYPTED|RECEIVED" {"Green"} "HANGING" {"Yellow"} default {"Red"} }
    Write-Host "  -> $r" -ForegroundColor $color
    
    $ss = if ($so.Length -gt 400) { $so.Substring($so.Length-400) } else { $so }
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nSERVER: $ss`n" -Encoding UTF8
    
    Stop-Job $sj -EA SilentlyContinue; Remove-Job $sj -EA SilentlyContinue
}

Kill-All
Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log; git commit -m "Batch v9 $timestamp"; git push 2>&1
