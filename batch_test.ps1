# FIFA 17 SSL Bypass - Batch Test v4
# 30+ patches tested automatically
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS2 {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Press(byte vk, byte scan) {
        keybd_event(vk, scan, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(50);
        keybd_event(vk, scan, KUP, UIntPtr.Zero);
    }
    public static void Enter() { Press(0x0D, 0x1C); }
    public static void Q() { Press(0x51, 0x10); }
}
"@

function Focus-FIFA {
    $p = Get-Process -Name FIFA17 -ErrorAction SilentlyContinue
    if ($p -and $p.MainWindowHandle -ne [IntPtr]::Zero) {
        [KS2]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 300
        return $true
    }
    return $false
}
function Send-Enter { if (Focus-FIFA) { [KS2]::Enter() } }
function Send-Q { if (Focus-FIFA) { [KS2]::Q() } }

function Kill-All {
    Stop-Process -Name FIFA17 -Force -ErrorAction SilentlyContinue
    Get-Process -Name node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep 3
}

function Launch-Game {
    Start-Process $gameExe
    for ($i = 0; $i -lt 30; $i++) {
        if (Get-Process -Name FIFA17 -ErrorAction SilentlyContinue) { break }
        Start-Sleep 1
    }
    Start-Sleep 10; Send-Enter
    Start-Sleep 5; Send-Enter
    Start-Sleep 5; Send-Enter
    Start-Sleep 5; Send-Enter
    Start-Sleep 5; Send-Enter
    Start-Sleep 10; Send-Enter  # dismiss first connection failure
    Start-Sleep 2
}

function Run-Frida($code) {
    $tmp = "$repoRoot\tmp_frida.js"
    $full = "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}"
    Set-Content $tmp $full -Encoding UTF8
    $proc = Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"
    $proc | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    if (!$proc.HasExited) { $proc | Stop-Process -Force }
    $out = (Get-Content "$repoRoot\fo.txt" -Raw -ErrorAction SilentlyContinue)
    Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -ErrorAction SilentlyContinue
    return $out
}


# ============================================================
# 30 patches covering every angle
# ============================================================
# Key addresses from code dumps:
# State 3 cert handler: +0x61262DC
#   CALL +0x6127B40 (cert_receive) at +0x61262E8
#   CALL +0x6127020 (cert_process) at +0x61262F0
#   TEST eax,eax / JLE (if <=0 goto error) at +0x61262F5
#   CALL +0x6124140 (on success) at +0x6126311
#   CALL +0x61279F0 (cert_finalize) at +0x6126334
#   State=4 set at +0x612631C
# Error path in state 3: +0x6126334 area, sets state=7
# State 5 error: +0x6126440-0x6126463
#   CALL +0x612E770 (error handler) at +0x612644E
# Error handler: +0x612E770
#   CALL +0x612D5D0 (disconnect) at +0x612E7B8
#   CALL +0x612BB40 at +0x612E7C0

$patches = @(
    # === GROUP A: Patch cert_process return value ===
    @{ name="A01_cert_process_ret1"; desc="cert_process ret 1"
       patch='Memory.protect(b.add(0x6127020),6,"rwx");b.add(0x6127020).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);'
       revert='Memory.protect(b.add(0x6127020),6,"rwx");b.add(0x6127020).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);' },
    @{ name="A02_cert_process_ret64"; desc="cert_process ret 0x40 (64)"
       patch='Memory.protect(b.add(0x6127020),6,"rwx");b.add(0x6127020).writeByteArray([0xB8,0x40,0x00,0x00,0x00,0xC3]);'
       revert='Memory.protect(b.add(0x6127020),6,"rwx");b.add(0x6127020).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);' },

    # === GROUP B: Patch the JLE after cert_process (force success branch) ===
    # At +0x61262F5: TEST eax,eax then JLE. JLE is 7E xx. Change to JMP (EB) or NOP.
    @{ name="B01_JLE_to_NOP_62F7"; desc="NOP the JLE after cert_process test"
       patch='var a=b.add(0x61262F7);Memory.protect(a,2,"rwx");a.writeByteArray([0x90,0x90]);'
       revert='var a=b.add(0x61262F7);Memory.protect(a,2,"rwx");a.writeByteArray([0x7E,0x36]);' },
    @{ name="B02_TEST_to_XOR_62F5"; desc="Change TEST eax,eax to XOR eax,eax (force zero=success)"
       patch='var a=b.add(0x61262F5);Memory.protect(a,2,"rwx");a.writeByteArray([0x31,0xC0]);'
       revert='var a=b.add(0x61262F5);Memory.protect(a,2,"rwx");a.writeByteArray([0x85,0xC0]);' },
    @{ name="B03_force_eax1_before_test"; desc="Insert MOV eax,1 before TEST (overwrite TEST+JLE)"
       patch='var a=b.add(0x61262F5);Memory.protect(a,4,"rwx");a.writeByteArray([0xB8,0x01,0x00,0x00]);'
       revert='var a=b.add(0x61262F5);Memory.protect(a,4,"rwx");a.writeByteArray([0x85,0xC0,0x7E,0x36]);' },

    # === GROUP C: Patch cert_receive to skip but not crash ===
    @{ name="C01_cert_receive_ret1"; desc="cert_receive ret 1"
       patch='Memory.protect(b.add(0x6127B40),6,"rwx");b.add(0x6127B40).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0xC3]);'
       revert='Memory.protect(b.add(0x6127B40),6,"rwx");b.add(0x6127B40).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);' },

    # === GROUP D: Patch the success-path function at +0x6124140 ===
    @{ name="D01_success_fn_ret0"; desc="Success fn +0x6124140 ret 0"
       patch='Memory.protect(b.add(0x6124140),6,"rwx");b.add(0x6124140).writeByteArray([0x31,0xC0,0xC3,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6124140),6,"rwx");b.add(0x6124140).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);' },
    @{ name="D02_success_fn_nop"; desc="NOP the CALL to success fn at +0x6126311"
       patch='Memory.protect(b.add(0x6126311),5,"rwx");b.add(0x6126311).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6126311),5,"rwx");b.add(0x6126311).writeByteArray([0xE8,0x2A,0xDE,0xFF,0xFF]);' },

    # === GROUP E: Patch cert_finalize ===
    @{ name="E01_cert_finalize_ret0"; desc="cert_finalize ret 0"
       patch='Memory.protect(b.add(0x61279F0),6,"rwx");b.add(0x61279F0).writeByteArray([0x31,0xC0,0xC3,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61279F0),6,"rwx");b.add(0x61279F0).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);' },

    # === GROUP F: Combined - skip verify but keep parsing ===
    @{ name="F01_NOP_JLE_AND_NOP_call644E"; desc="NOP JLE at +0x61262F7 AND NOP error CALL at +0x612644E"
       patch='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x7E,0x36]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' },
    @{ name="F02_force_eax1_AND_NOP_call644E"; desc="Force eax=1 at +0x61262F5 AND NOP error CALL"
       patch='Memory.protect(b.add(0x61262F5),4,"rwx");b.add(0x61262F5).writeByteArray([0xB8,0x01,0x00,0x00]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61262F5),4,"rwx");b.add(0x61262F5).writeByteArray([0x85,0xC0,0x7E,0x36]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' },
    @{ name="F03_NOP_JLE_AND_disconnect_ret"; desc="NOP JLE + disconnect ret"
       patch='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x612D5D0),1,"rwx");b.add(0x612D5D0).writeU8(0xC3);'
       revert='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x7E,0x36]);Memory.protect(b.add(0x612D5D0),1,"rwx");b.add(0x612D5D0).writeU8(0x48);' },

    # === GROUP G: Patch the error path in State 3 directly ===
    # At +0x612632D: the error sets state=7. Find and NOP it.
    @{ name="G01_NOP_state7_set_6263BC"; desc="NOP state=7 write at +0x61263BC area"
       patch='Memory.protect(b.add(0x61263BE),7,"rwx");b.add(0x61263BE).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61263BE),7,"rwx");b.add(0x61263BE).writeByteArray([0xC7,0x83,0x8C,0x00,0x00,0x00,0x07]);' },

    # === GROUP H: Patch at the recv level - make recv handler skip cert check ===
    @{ name="H01_NOP_cert_process_call"; desc="NOP the CALL to cert_process at +0x61262F0"
       patch='Memory.protect(b.add(0x61262F0),5,"rwx");b.add(0x61262F0).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61262F0),5,"rwx");b.add(0x61262F0).writeByteArray([0xE8,0x2B,0x0D,0x00,0x00]);' },
    @{ name="H02_NOP_cert_process_AND_force_state4"; desc="NOP cert_process CALL + force state=4"
       patch='Memory.protect(b.add(0x61262F0),9,"rwx");b.add(0x61262F0).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61262F0),9,"rwx");b.add(0x61262F0).writeByteArray([0xE8,0x2B,0x0D,0x00,0x00,0x85,0xC0,0x7E,0x36]);' },

    # === GROUP I: Patch the error handler function ===
    @{ name="I01_error_E770_ret0"; desc="Error handler +0x612E770 xor eax,eax;ret"
       patch='Memory.protect(b.add(0x612E770),3,"rwx");b.add(0x612E770).writeByteArray([0x31,0xC0,0xC3]);'
       revert='Memory.protect(b.add(0x612E770),3,"rwx");b.add(0x612E770).writeByteArray([0x48,0x89,0x5C]);' },
    @{ name="I02_error_E810_ret0"; desc="Function +0x612E810 xor eax,eax;ret"
       patch='Memory.protect(b.add(0x612E810),3,"rwx");b.add(0x612E810).writeByteArray([0x31,0xC0,0xC3]);'
       revert='Memory.protect(b.add(0x612E810),3,"rwx");b.add(0x612E810).writeByteArray([0x48,0x89,0x5C]);' },
    @{ name="I03_fn_BB40_ret0"; desc="Function +0x612BB40 xor eax,eax;ret"
       patch='Memory.protect(b.add(0x612BB40),3,"rwx");b.add(0x612BB40).writeByteArray([0x31,0xC0,0xC3]);'
       revert='Memory.protect(b.add(0x612BB40),3,"rwx");b.add(0x612BB40).writeByteArray([0x48,0x89,0x5C]);' },

    # === GROUP J: Aggressive combos ===
    @{ name="J01_NOP_JLE_NOP_call644E_disc_ret"; desc="NOP JLE + NOP error CALL + disconnect ret"
       patch='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612D5D0),1,"rwx");b.add(0x612D5D0).writeU8(0xC3);'
       revert='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x7E,0x36]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);Memory.protect(b.add(0x612D5D0),1,"rwx");b.add(0x612D5D0).writeU8(0x48);' },
    @{ name="J02_force_eax1_NOP_state7_disc_ret"; desc="Force eax=1 + NOP state7 + disconnect ret"
       patch='Memory.protect(b.add(0x61262F5),4,"rwx");b.add(0x61262F5).writeByteArray([0xB8,0x01,0x00,0x00]);Memory.protect(b.add(0x61263BE),7,"rwx");b.add(0x61263BE).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612D5D0),1,"rwx");b.add(0x612D5D0).writeU8(0xC3);'
       revert='Memory.protect(b.add(0x61262F5),4,"rwx");b.add(0x61262F5).writeByteArray([0x85,0xC0,0x7E,0x36]);Memory.protect(b.add(0x61263BE),7,"rwx");b.add(0x61263BE).writeByteArray([0xC7,0x83,0x8C,0x00,0x00,0x00,0x07]);Memory.protect(b.add(0x612D5D0),1,"rwx");b.add(0x612D5D0).writeU8(0x48);' },
    @{ name="J03_replace_cert_process_AND_NOP_644E"; desc="cert_process ret 0x40 + NOP error CALL"
       patch='Memory.protect(b.add(0x6127020),6,"rwx");b.add(0x6127020).writeByteArray([0xB8,0x40,0x00,0x00,0x00,0xC3]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x6127020),6,"rwx");b.add(0x6127020).writeByteArray([0x48,0x89,0x5C,0x24,0x08,0x57]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' },
    @{ name="J04_NOP_cert_process_force_state4_NOP_644E"; desc="Skip cert_process + force eax=1 + NOP error CALL"
       patch='Memory.protect(b.add(0x61262F0),9,"rwx");b.add(0x61262F0).writeByteArray([0xB8,0x01,0x00,0x00,0x00,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x61262F0),9,"rwx");b.add(0x61262F0).writeByteArray([0xE8,0x2B,0x0D,0x00,0x00,0x85,0xC0,0x7E,0x36]);Memory.protect(b.add(0x612644E),5,"rwx");b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);' },

    # === GROUP K: Patch the Aim4kill cert + NOP verify ===
    @{ name="K01_NOP_JLE_only"; desc="Just NOP the JLE at +0x61262F7 (let cert_process run but ignore result)"
       patch='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);'
       revert='Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x7E,0x36]);' },
    @{ name="K02_JLE_to_JG"; desc="Change JLE to JG at +0x61262F7 (invert condition)"
       patch='Memory.protect(b.add(0x61262F7),1,"rwx");b.add(0x61262F7).writeU8(0x7F);'
       revert='Memory.protect(b.add(0x61262F7),1,"rwx");b.add(0x61262F7).writeU8(0x7E);' },

    # === GROUP L: NOP all state=7 writes in the function ===
    @{ name="L01_NOP_all_state7"; desc="NOP all state=7 writes in cert handler area"
       patch='Memory.protect(b.add(0x612620E),7,"rwx");b.add(0x612620E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612626D),7,"rwx");b.add(0x612626D).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x61263BE),7,"rwx");b.add(0x61263BE).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90]);Memory.protect(b.add(0x612633C),7,"rwx");b.add(0x612633C).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
       revert='Memory.protect(b.add(0x612620E),7,"rwx");b.add(0x612620E).writeByteArray([0xC7,0x83,0x8C,0x00,0x00,0x00,0x07]);Memory.protect(b.add(0x612626D),7,"rwx");b.add(0x612626D).writeByteArray([0xC7,0x83,0x8C,0x00,0x00,0x00,0x07]);Memory.protect(b.add(0x61263BE),7,"rwx");b.add(0x61263BE).writeByteArray([0xC7,0x83,0x8C,0x00,0x00,0x00,0x07]);Memory.protect(b.add(0x612633C),7,"rwx");b.add(0x612633C).writeByteArray([0xC7,0x83,0x8C,0x00,0x00,0x00,0x07]);' }
)


# ============================================================
# Main loop
# ============================================================
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v4 ($timestamp) === $($patches.Count) patches`n" -Encoding UTF8
Write-Host "=== BATCH v4 - $($patches.Count) patches ===" -ForegroundColor Cyan

Kill-All
$serverJob = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2
Write-Host "Launching game..." -ForegroundColor Yellow
Launch-Game
Write-Host "Game ready." -ForegroundColor Green

$n = 0
foreach ($p in $patches) {
    $n++
    Write-Host "[$n/$($patches.Count)] $($p.name)" -ForegroundColor Yellow
    
    if (-not (Get-Process -Name FIFA17 -ErrorAction SilentlyContinue)) {
        Write-Host "  CRASHED - relaunching" -ForegroundColor Red
        Add-Content $resultsFile "[$n] $($p.name) | CRASHED_BEFORE | $($p.desc)`n"
        Stop-Job $serverJob -ErrorAction SilentlyContinue; Remove-Job $serverJob -ErrorAction SilentlyContinue
        Kill-All
        $serverJob = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
        Start-Sleep 2; Launch-Game
    }
    
    Receive-Job $serverJob 2>&1 | Out-Null  # drain
    
    $fo = Run-Frida $p.patch
    Start-Sleep 1
    Send-Q; Start-Sleep 12
    
    $so = (Receive-Job $serverJob 2>&1 | Out-String).Trim()
    
    $r = "UNKNOWN"
    if ($so -match "Phase=.*received") { $r = "RECEIVED_DATA" }
    if ($so -match "Record: type=0x16") { $r = "TLS_HANDSHAKE_DATA" }
    if ($so -match "Encrypted Finished") { $r = "TLS_COMPLETE" }
    if ($so -match "Decrypted") { $r = "DECRYPTED" }
    if ($so -match "ECONNRESET") { $r = "ECONNRESET" }
    if ($so -match "15 03 00 00 02 02") { $r = "SSL_ALERT" }
    if ($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "Disconnected") { $r = "HANGING" }
    if ($so -eq "") { $r = "NO_CONNECTION" }
    if (-not (Get-Process -Name FIFA17 -ErrorAction SilentlyContinue)) { $r += "+CRASHED" }
    
    $color = switch -Regex ($r) { "RECEIVED|TLS_|DECRYPTED" {"Green"} "HANGING" {"Yellow"} default {"Red"} }
    Write-Host "  -> $r" -ForegroundColor $color
    
    $sShort = if ($so.Length -gt 200) { $so.Substring($so.Length-200) } else { $so }
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nSERVER: $sShort`n" -Encoding UTF8
    
    if ($p.revert) { Run-Frida $p.revert | Out-Null; Start-Sleep 1 }
    Send-Enter; Start-Sleep 2
}

Stop-Job $serverJob -ErrorAction SilentlyContinue; Remove-Job $serverJob -ErrorAction SilentlyContinue
Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log; git commit -m "Batch v4 results $timestamp"; git push 2>&1
