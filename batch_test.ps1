# FIFA 17 SSL Bypass - Batch Test Runner v2
# Keeps game running between tests. Uses Frida to apply/revert patches.
# Usage: .\batch_test.ps1

$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$serverScript = "$repoRoot\server-standalone\server.mjs"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KS {
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
        [KS]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 300
        return $true
    }
    return $false
}

function Send-Enter { if (Focus-FIFA) { [KS]::Enter() } }
function Send-Q { if (Focus-FIFA) { [KS]::Q() } }

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
    Start-Sleep 3; Send-Enter
    # Wait for first connection attempt to finish
    Start-Sleep 10
    # Dismiss the failure dialog
    Send-Enter
    Start-Sleep 2
}

function Run-Frida-Patch($scriptContent) {
    $tmp = "$repoRoot\temp_patch.js"
    Set-Content $tmp $scriptContent -Encoding UTF8
    # Frida 17: no --no-pause flag, use -e for eval or just -l
    $output = & frida -n FIFA17.exe -l $tmp 2>&1 | Out-String
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    return $output
}


# ============================================================
# Patches - each is a Frida script + a revert script
# The Frida script patches bytes, then calls send() to signal done,
# then the script exits so Frida detaches cleanly.
# ============================================================

# Helper: wrap patch script to auto-exit after patching
function Wrap-Script($code) {
    return @"
var b = Process.getModuleByName("FIFA17.exe").base;
try {
$code
    send("OK");
} catch(e) {
    send("ERR: " + e.message);
}
"@
}

# Helper: wrap revert script
function Wrap-Revert($code) {
    return Wrap-Script $code
}

$patches = @(
    @{
        name = "P01_JNE_to_JMP_6126440"
        desc = "JNE->JMP at +0x6126440"
        patch = 'Memory.protect(b.add(0x6126440),1,"rwx"); b.add(0x6126440).writeU8(0xEB);'
        revert = 'Memory.protect(b.add(0x6126440),1,"rwx"); b.add(0x6126440).writeU8(0x75);'
    },
    @{
        name = "P02_NOP_call_612644E"
        desc = "NOP CALL at +0x612644E"
        patch = 'Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
        revert = 'Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);'
    },
    @{
        name = "P03_error_handler_ret0"
        desc = "Error handler +0x612E770 ret 0"
        patch = 'Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x31,0xC0,0xC3]);'
        revert = 'Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x48,0x89,0x5C]);'
    },
    @{
        name = "P04_disconnect_5D0_ret"
        desc = "Disconnect +0x612D5D0 ret"
        patch = 'Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0xC3);'
        revert = 'Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0x48);'
    },
    @{
        name = "P05_disconnect_730_ret"
        desc = "Disconnect caller +0x612D730 ret"
        patch = 'Memory.protect(b.add(0x612D730),1,"rwx"); b.add(0x612D730).writeU8(0xC3);'
        revert = 'Memory.protect(b.add(0x612D730),1,"rwx"); b.add(0x612D730).writeU8(0x48);'
    },
    @{
        name = "P06_NOP_call_AND_disconnect"
        desc = "NOP CALL +0x612644E AND disconnect ret"
        patch = 'Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]); Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0xC3);'
        revert = 'Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]); Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0x48);'
    },
    @{
        name = "P07_JMP_AND_disconnect"
        desc = "JMP +0x6126440 AND disconnect ret"
        patch = 'Memory.protect(b.add(0x6126440),1,"rwx"); b.add(0x6126440).writeU8(0xEB); Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0xC3);'
        revert = 'Memory.protect(b.add(0x6126440),1,"rwx"); b.add(0x6126440).writeU8(0x75); Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0x48);'
    },
    @{
        name = "P08_NOP_both_JNE"
        desc = "NOP both JNE at +0x6126440 and +0x6126449"
        patch = 'Memory.protect(b.add(0x6126440),2,"rwx"); b.add(0x6126440).writeByteArray([0x90,0x90]); Memory.protect(b.add(0x6126449),2,"rwx"); b.add(0x6126449).writeByteArray([0x90,0x90]);'
        revert = 'Memory.protect(b.add(0x6126440),2,"rwx"); b.add(0x6126440).writeByteArray([0x75,0x21]); Memory.protect(b.add(0x6126449),2,"rwx"); b.add(0x6126449).writeByteArray([0x75,0x18]);'
    },
    @{
        name = "P09_NOP_disconnect_call_E7B8"
        desc = "NOP disconnect CALL at +0x612E7B8"
        patch = 'Memory.protect(b.add(0x612E7B8),5,"rwx"); b.add(0x612E7B8).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
        revert = 'Memory.protect(b.add(0x612E7B8),5,"rwx"); b.add(0x612E7B8).writeByteArray([0xE8,0x13,0xEE,0xFF,0xFF]);'
    },
    @{
        name = "P10_NOP_E7B8_AND_E7C0"
        desc = "NOP both CALLs at +0x612E7B8 and +0x612E7C0"
        patch = 'Memory.protect(b.add(0x612E7B8),13,"rwx"); b.add(0x612E7B8).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
        revert = 'Memory.protect(b.add(0x612E7B8),13,"rwx"); b.add(0x612E7B8).writeByteArray([0xE8,0x13,0xEE,0xFF,0xFF,0xEB,0x09,0xBC,0xE8,0x7B,0xD3,0xFF,0xFF]);'
    },
    @{
        name = "P11_all_disconnects_ret"
        desc = "All disconnect functions ret (5D0 + 730 + E770)"
        patch = 'Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0xC3); Memory.protect(b.add(0x612D730),1,"rwx"); b.add(0x612D730).writeU8(0xC3); Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x31,0xC0,0xC3]);'
        revert = 'Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0x48); Memory.protect(b.add(0x612D730),1,"rwx"); b.add(0x612D730).writeU8(0x48); Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x48,0x89,0x5C]);'
    },
    @{
        name = "P12_kitchen_sink"
        desc = "JMP+NOP_CALL+disconnect_ret+error_ret0 (everything)"
        patch = 'Memory.protect(b.add(0x6126440),1,"rwx"); b.add(0x6126440).writeU8(0xEB); Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]); Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0xC3); Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x31,0xC0,0xC3]);'
        revert = 'Memory.protect(b.add(0x6126440),1,"rwx"); b.add(0x6126440).writeU8(0x75); Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]); Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0x48); Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x48,0x89,0x5C]);'
    }
)


# ============================================================
# Main
# ============================================================

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH TEST v2 ($timestamp) === Patches: $($patches.Count)`n" -Encoding UTF8
Write-Host "=== BATCH TEST v2 - $($patches.Count) patches ===" -ForegroundColor Cyan

# Kill old stuff, start server, launch game once
Kill-All
$serverJob = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
Start-Sleep 2
Write-Host "Launching game (one time)..." -ForegroundColor Yellow
Launch-Game
Write-Host "Game ready. Starting tests..." -ForegroundColor Green

$testNum = 0
foreach ($patch in $patches) {
    $testNum++
    Write-Host "`n[$testNum/$($patches.Count)] $($patch.name): $($patch.desc)" -ForegroundColor Yellow
    
    # Check game is still running
    if (-not (Get-Process -Name FIFA17 -ErrorAction SilentlyContinue)) {
        Write-Host "  Game crashed! Relaunching..." -ForegroundColor Red
        Add-Content $resultsFile "[$testNum] $($patch.name): GAME_CRASHED_BEFORE_TEST`n"
        # Restart server too
        Stop-Job $serverJob -ErrorAction SilentlyContinue
        Remove-Job $serverJob -ErrorAction SilentlyContinue
        Kill-All
        $serverJob = Start-Job -ScriptBlock { param($r); node "$r\server-standalone\server.mjs" 2>&1 } -ArgumentList $repoRoot
        Start-Sleep 2
        Launch-Game
    }
    
    # Drain old server output
    Receive-Job $serverJob 2>&1 | Out-Null
    
    # Apply patch via Frida
    Write-Host "  Applying patch..." -ForegroundColor Gray
    $patchScript = Wrap-Script $patch.patch
    $fridaOut = Run-Frida-Patch $patchScript
    Write-Host "  Frida: $($fridaOut.Trim())" -ForegroundColor Gray
    Start-Sleep 1
    
    # Trigger connection attempt #2 by pressing Q
    Write-Host "  Pressing Q..." -ForegroundColor Gray
    Send-Q
    Start-Sleep 12
    
    # Collect server output
    $serverOut = (Receive-Job $serverJob 2>&1 | Out-String).Trim()
    
    # Classify result
    $result = "UNKNOWN"
    if ($serverOut -match "Phase=.*received") { $result = "RECEIVED_DATA" }
    if ($serverOut -match "Encrypted Finished") { $result = "TLS_COMPLETE" }
    if ($serverOut -match "Decrypted") { $result = "DECRYPTED" }
    if ($serverOut -match "Record: type=0x16.*Handshake type: 0x10") { $result = "CLIENT_KEY_EXCHANGE" }
    if ($serverOut -match "ECONNRESET") { $result = "ECONNRESET" }
    if ($serverOut -match "15 03 00 00 02 02 2a") { $result = "BAD_CERT_ALERT" }
    if ($serverOut -match "Waiting for ClientKeyExchange" -and $serverOut -notmatch "ECONNRESET" -and $serverOut -notmatch "Disconnected") { $result = "HANGING_NO_DISCONNECT" }
    if ($serverOut -eq "") { $result = "NO_CONNECTION" }
    
    if (-not (Get-Process -Name FIFA17 -ErrorAction SilentlyContinue)) { $result += "+CRASHED" }
    
    $color = if ($result -match "KEY_EXCHANGE|TLS_COMPLETE|DECRYPTED|RECEIVED") { "Green" } elseif ($result -match "HANGING") { "Yellow" } else { "Red" }
    Write-Host "  RESULT: $result" -ForegroundColor $color
    
    # Log
    Add-Content $resultsFile "[$testNum] $($patch.name) | $result | $($patch.desc)`nFRIDA: $($fridaOut.Trim())`nSERVER: $($serverOut.Substring([Math]::Max(0,$serverOut.Length-300)))`n" -Encoding UTF8
    
    # Revert patch
    Write-Host "  Reverting..." -ForegroundColor Gray
    $revertScript = Wrap-Revert $patch.revert
    Run-Frida-Patch $revertScript | Out-Null
    Start-Sleep 1
    
    # Dismiss failure dialog (press Enter)
    Send-Enter
    Start-Sleep 2
}

# Cleanup
Stop-Job $serverJob -ErrorAction SilentlyContinue
Remove-Job $serverJob -ErrorAction SilentlyContinue

Write-Host "`n=== ALL TESTS COMPLETE ===" -ForegroundColor Green
Write-Host "Results in batch-results.log" -ForegroundColor Green

git add batch-results.log
git commit -m "Batch v2 results $timestamp"
git push 2>&1
Write-Host "Pushed." -ForegroundColor Cyan
