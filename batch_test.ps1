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
    # Wait for first connection attempt to finish
    Start-Sleep 10
    # Dismiss the failure dialog
    Send-Enter
    Start-Sleep 2
}

function Run-Frida-Patch($scriptContent) {
    $tmp = "$repoRoot\temp_patch.js"
    # Add process.exit() so Frida detaches after patching
    $fullScript = $scriptContent + "`nsetTimeout(function(){},100);"
    Set-Content $tmp $fullScript -Encoding UTF8
    $output = ""
    try {
        # Use --timeout to auto-exit, pipe to get output
        $proc = Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\frida_out.txt" -RedirectStandardError "$repoRoot\frida_err.txt"
        $proc | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
        if (!$proc.HasExited) { $proc | Stop-Process -Force }
        $output = (Get-Content "$repoRoot\frida_out.txt" -Raw -ErrorAction SilentlyContinue) + (Get-Content "$repoRoot\frida_err.txt" -Raw -ErrorAction SilentlyContinue)
    } catch {
        $output = "ERROR: $_"
    }
    Remove-Item $tmp,"$repoRoot\frida_out.txt","$repoRoot\frida_err.txt" -Force -ErrorAction SilentlyContinue
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
    # --- DIAGNOSTIC: Dump State 3 code to find cert verify calls ---
    @{
        name = "D01_dump_state3"
        desc = "Dump 256 bytes at State 3 (+0x61262DC)"
        patch = @'
var a = b.add(0x61262DC);
var h = "";
for (var i = 0; i < 256; i++) {
    h += ("0"+a.add(i).readU8().toString(16)).slice(-2)+" ";
    if ((i+1)%32===0) { send("S3 +"+(0x61262DC+i-31).toString(16)+": "+h); h=""; }
}
// Find all CALL instructions
for (var i = 0; i < 256; i++) {
    if (a.add(i).readU8()===0xE8) {
        var d=a.add(i+1).readS32();
        send("CALL exe+"+(a.add(i).sub(b))+" -> exe+"+(a.add(i+5).add(d).sub(b)));
    }
}
'@
        revert = ''
    },
    # --- DIAGNOSTIC: Dump code before State 3 (cert receive handler) ---
    @{
        name = "D02_dump_before_state3"
        desc = "Dump 256 bytes before State 3 (+0x61261DC)"
        patch = @'
var a = b.add(0x61261DC);
var h = "";
for (var i = 0; i < 256; i++) {
    h += ("0"+a.add(i).readU8().toString(16)).slice(-2)+" ";
    if ((i+1)%32===0) { send("PRE3 +"+(0x61261DC+i-31).toString(16)+": "+h); h=""; }
}
for (var i = 0; i < 256; i++) {
    if (a.add(i).readU8()===0xE8) {
        var d=a.add(i+1).readS32();
        send("CALL exe+"+(a.add(i).sub(b))+" -> exe+"+(a.add(i+5).add(d).sub(b)));
    }
}
'@
        revert = ''
    },
    # --- DIAGNOSTIC: Dump cert_process function ---
    @{
        name = "D03_dump_cert_process"
        desc = "Dump 128 bytes at cert_process (+0x6127020)"
        patch = @'
var a = b.add(0x6127020);
var h = "";
for (var i = 0; i < 128; i++) {
    h += ("0"+a.add(i).readU8().toString(16)).slice(-2)+" ";
    if ((i+1)%32===0) { send("CP +"+(0x6127020+i-31).toString(16)+": "+h); h=""; }
}
for (var i = 0; i < 128; i++) {
    if (a.add(i).readU8()===0xE8) {
        var d=a.add(i+1).readS32();
        send("CALL exe+"+(a.add(i).sub(b))+" -> exe+"+(a.add(i+5).add(d).sub(b)));
    }
}
'@
        revert = ''
    },
    # --- DIAGNOSTIC: Dump cert_verify function ---
    @{
        name = "D04_dump_cert_verify"
        desc = "Dump 128 bytes at cert_verify (+0x6124140)"
        patch = @'
var a = b.add(0x6124140);
var h = "";
for (var i = 0; i < 128; i++) {
    h += ("0"+a.add(i).readU8().toString(16)).slice(-2)+" ";
    if ((i+1)%32===0) { send("CV +"+(0x6124140+i-31).toString(16)+": "+h); h=""; }
}
for (var i = 0; i < 128; i++) {
    if (a.add(i).readU8()===0xE8) {
        var d=a.add(i+1).readS32();
        send("CALL exe+"+(a.add(i).sub(b))+" -> exe+"+(a.add(i+5).add(d).sub(b)));
    }
}
'@
        revert = ''
    },
    # --- PATCH: NOP CALL at +0x612644E (known working - prevents disconnect) ---
    @{
        name = "P02_NOP_call_612644E"
        desc = "NOP CALL at +0x612644E (baseline - prevents disconnect)"
        patch = 'Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);'
        revert = 'Memory.protect(b.add(0x612644E),5,"rwx"); b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00]);'
    },
    # --- PATCH: NOP CALL + NOP error state writes (v17 approach) ---
    @{
        name = "P13_NOP_call_AND_state_writes"
        desc = "NOP CALL+state writes at +0x612644E/6126453/612645C"
        patch = 'Memory.protect(b.add(0x612644E),21,"rwx"); b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
        revert = 'Memory.protect(b.add(0x612644E),21,"rwx"); b.add(0x612644E).writeByteArray([0xE8,0x1D,0x83,0x00,0x00,0x66,0xC7,0x83,0x1F,0x0C,0x00,0x00,0x00,0x01,0x40,0x88,0xBB,0x21,0x0C,0x00,0x00]);'
    },
    # --- PATCH: All disconnects ret (known working) + NOP error state writes ---
    @{
        name = "P14_all_disc_ret_AND_NOP_state"
        desc = "All disconnects ret + NOP state writes"
        patch = 'Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0xC3); Memory.protect(b.add(0x612D730),1,"rwx"); b.add(0x612D730).writeU8(0xC3); Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x31,0xC0,0xC3]); Memory.protect(b.add(0x6126453),14,"rwx"); b.add(0x6126453).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90]);'
        revert = 'Memory.protect(b.add(0x612D5D0),1,"rwx"); b.add(0x612D5D0).writeU8(0x48); Memory.protect(b.add(0x612D730),1,"rwx"); b.add(0x612D730).writeU8(0x48); Memory.protect(b.add(0x612E770),3,"rwx"); b.add(0x612E770).writeByteArray([0x48,0x89,0x5C]); Memory.protect(b.add(0x6126453),14,"rwx"); b.add(0x6126453).writeByteArray([0x66,0xC7,0x83,0x1F,0x0C,0x00,0x00,0x00,0x01,0x40,0x88,0xBB,0x21,0x0C]);'
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
