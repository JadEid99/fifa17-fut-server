# FIFA 17 SSL Bypass - Batch Test Runner
# Runs multiple Frida patches sequentially, auto-launching the game each time.
# Usage: .\batch_test.ps1

$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$serverScript = "$repoRoot\server-standalone\server.mjs"
$resultsFile = "$repoRoot\batch-results.log"

# Helper: send Enter key to FIFA 17
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KeySender {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const byte VK_RETURN = 0x0D;
    public const uint KEYEVENTF_KEYUP = 0x0002;
    public static void PressEnter() {
        keybd_event(VK_RETURN, 0x1C, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(50);
        keybd_event(VK_RETURN, 0x1C, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }
    public static void PressQ() {
        keybd_event(0x51, 0x10, 0, UIntPtr.Zero);
        System.Threading.Thread.Sleep(50);
        keybd_event(0x51, 0x10, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }
}
"@

function Send-EnterToFIFA {
    $proc = Get-Process -Name FIFA17 -ErrorAction SilentlyContinue
    if ($proc -and $proc.MainWindowHandle -ne [IntPtr]::Zero) {
        [KeySender]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 200
        [KeySender]::PressEnter()
    }
}

function Send-QToFIFA {
    $proc = Get-Process -Name FIFA17 -ErrorAction SilentlyContinue
    if ($proc -and $proc.MainWindowHandle -ne [IntPtr]::Zero) {
        [KeySender]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 200
        [KeySender]::PressQ()
    }
}

function Kill-Everything {
    Stop-Process -Name FIFA17 -Force -ErrorAction SilentlyContinue
    Get-Process -Name node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep 3
}

function Launch-And-Navigate {
    Start-Process $gameExe
    $timeout = 30
    for ($i = 0; $i -lt $timeout; $i++) {
        if (Get-Process -Name FIFA17 -ErrorAction SilentlyContinue) { break }
        Start-Sleep 1
    }
    Start-Sleep 10
    Send-EnterToFIFA; Start-Sleep 5
    Send-EnterToFIFA; Start-Sleep 5
    Send-EnterToFIFA; Start-Sleep 5
    Send-EnterToFIFA; Start-Sleep 5
    Send-EnterToFIFA; Start-Sleep 3
    Send-EnterToFIFA
}

# ============================================================
# Define all patches to test
# Each patch is a Frida script that applies a specific modification
# ============================================================

$patches = @(
    # --- GROUP 1: Patch the JNE at State 5 error check ---
    @{
        name = "G1_JNE_to_JMP_6126440"
        desc = "Change JNE to JMP at +0x6126440 (skip error path entirely)"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x6126440);
Memory.protect(a, 1, 'rwx');
a.writeU8(0xEB);
'@
    },
    @{
        name = "G1_NOP_call_612644E"
        desc = "NOP the CALL to error handler at +0x612644E"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x612644E);
Memory.protect(a, 5, 'rwx');
a.writeByteArray([0x90,0x90,0x90,0x90,0x90]);
'@
    },
    @{
        name = "G1_NOP_call_AND_JNE"
        desc = "NOP CALL at +0x612644E AND change JNE at +0x6126449 to JMP"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
Memory.protect(b.add(0x612644E), 5, 'rwx');
b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);
Memory.protect(b.add(0x6126449), 1, 'rwx');
b.add(0x6126449).writeU8(0xEB);
'@
    },

    # --- GROUP 2: Patch the error handler function itself ---
    @{
        name = "G2_error_handler_ret0"
        desc = "Make error handler at +0x612E770 return 0 immediately"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x612E770);
Memory.protect(a, 3, 'rwx');
a.writeByteArray([0x31,0xC0,0xC3]);
'@
    },

    # --- GROUP 3: Patch the disconnect function ---
    @{
        name = "G3_disconnect_ret"
        desc = "Make disconnect at +0x612D5D0 return immediately"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x612D5D0);
Memory.protect(a, 1, 'rwx');
a.writeU8(0xC3);
'@
    },
    @{
        name = "G3_disconnect_730_ret"
        desc = "Make disconnect caller at +0x612D730 return immediately"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x612D730);
Memory.protect(a, 1, 'rwx');
a.writeU8(0xC3);
'@
    },

    # --- GROUP 4: Patch State 3 (Certificate processing) ---
    @{
        name = "G4_state3_dump"
        desc = "Dump State 3 code at +0x61262DC and find CALL instructions"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x61262DC);
var hex = "";
for (var i = 0; i < 128; i++) {
    hex += ("0"+a.add(i).readU8().toString(16)).slice(-2)+" ";
    if ((i+1)%32===0) { send("STATE3 +"+(0x61262DC+i-31).toString(16)+": "+hex); hex=""; }
}
for (var i = 0; i < 128; i++) {
    if (a.add(i).readU8() === 0xE8) {
        var d = a.add(i+1).readS32();
        var t = a.add(i+5).add(d);
        send("CALL at exe+"+(a.add(i).sub(b))+(" -> exe+")+t.sub(b));
    }
}
'@
    },

    # --- GROUP 5: Patch cert verify/process functions from NEXT_SESSION_PLAN ---
    @{
        name = "G5_cert_process_ret0"
        desc = "Make cert process at +0x6127020 return 0"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x6127020);
Memory.protect(a, 3, 'rwx');
a.writeByteArray([0x31,0xC0,0xC3]);
'@
    },
    @{
        name = "G5_cert_receive_ret0"
        desc = "Make cert receive at +0x6127B40 return 0"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x6127B40);
Memory.protect(a, 3, 'rwx');
a.writeByteArray([0x31,0xC0,0xC3]);
'@
    },
    @{
        name = "G5_cert_finalize_ret0"
        desc = "Make cert finalize at +0x61279F0 return 0"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
var a = b.add(0x61279F0);
Memory.protect(a, 3, 'rwx');
a.writeByteArray([0x31,0xC0,0xC3]);
'@
    },

    # --- GROUP 6: Combined patches ---
    @{
        name = "G6_NOP_call_AND_disconnect_ret"
        desc = "NOP CALL at +0x612644E AND make disconnect +0x612D5D0 return"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
Memory.protect(b.add(0x612644E), 5, 'rwx');
b.add(0x612644E).writeByteArray([0x90,0x90,0x90,0x90,0x90]);
Memory.protect(b.add(0x612D5D0), 1, 'rwx');
b.add(0x612D5D0).writeU8(0xC3);
'@
    },
    @{
        name = "G6_error_handler_ret0_AND_disconnect_ret"
        desc = "Error handler ret 0 AND disconnect ret"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
Memory.protect(b.add(0x612E770), 3, 'rwx');
b.add(0x612E770).writeByteArray([0x31,0xC0,0xC3]);
Memory.protect(b.add(0x612D5D0), 1, 'rwx');
b.add(0x612D5D0).writeU8(0xC3);
'@
    },
    @{
        name = "G6_JMP_6126440_AND_disconnect_ret"
        desc = "JMP at +0x6126440 AND disconnect ret at +0x612D5D0"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
Memory.protect(b.add(0x6126440), 1, 'rwx');
b.add(0x6126440).writeU8(0xEB);
Memory.protect(b.add(0x612D5D0), 1, 'rwx');
b.add(0x612D5D0).writeU8(0xC3);
'@
    },

    # --- GROUP 7: Patch the second JNE at +0x6126449 ---
    @{
        name = "G7_JNE_to_NOP_6126449"
        desc = "NOP the JNE at +0x6126449 (force fall-through to error handler)"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
Memory.protect(b.add(0x6126449), 2, 'rwx');
b.add(0x6126449).writeByteArray([0x90,0x90]);
'@
    },
    @{
        name = "G7_CMP_byte_patch_C20"
        desc = "Set [rbx+0xC20] to 1 via the CMP check - patch CMP to always succeed"
        script = @'
var b = Process.getModuleByName("FIFA17.exe").base;
Memory.protect(b.add(0x6126442), 7, 'rwx');
b.add(0x6126442).writeByteArray([0x90,0x90,0x90,0x90,0x90,0x90,0x90]);
Memory.protect(b.add(0x6126449), 2, 'rwx');
b.add(0x6126449).writeByteArray([0xEB,0x18]);
'@
    }
)


# ============================================================
# Main test loop
# ============================================================

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$header = "=== BATCH TEST RESULTS ($timestamp) ===`n"
$header += "Total patches to test: $($patches.Count)`n"
Set-Content $resultsFile $header -Encoding UTF8
Write-Host $header -ForegroundColor Cyan

$testNum = 0
foreach ($patch in $patches) {
    $testNum++
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "TEST $testNum/$($patches.Count): $($patch.name)" -ForegroundColor Yellow
    Write-Host "  $($patch.desc)" -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Kill everything
    Kill-Everything
    
    # Start server
    $serverJob = Start-Job -ScriptBlock {
        param($repoRoot)
        node "$repoRoot\server-standalone\server.mjs" 2>&1
    } -ArgumentList $repoRoot
    Start-Sleep 2
    
    # Launch game
    Write-Host "  Launching FIFA 17..."
    Launch-And-Navigate
    
    # Wait for Denuvo to unpack
    Write-Host "  Waiting 5s for Denuvo..."
    Start-Sleep 5
    
    # Write Frida script to temp file
    $fridaScript = "$repoRoot\temp_patch.js"
    Set-Content $fridaScript $patch.script -Encoding UTF8
    
    # Apply Frida patch
    Write-Host "  Applying Frida patch..."
    $fridaOutput = ""
    try {
        $fridaOutput = & frida -n FIFA17.exe -l $fridaScript --no-pause -q 2>&1 | Out-String
        Start-Sleep 2
    } catch {
        $fridaOutput = "FRIDA ERROR: $_"
    }
    
    # Wait for connection attempt (game should auto-connect during launch)
    # Send Q to open Ultimate Team which triggers connection attempt #2
    Write-Host "  Triggering connection attempt #2 (pressing Q)..."
    Send-QToFIFA
    Start-Sleep 15
    
    # Collect server output
    $serverOutput = Receive-Job $serverJob 2>&1 | Out-String
    Stop-Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job $serverJob -ErrorAction SilentlyContinue
    
    # Analyze result
    $result = "UNKNOWN"
    if ($serverOutput -match "ClientKeyExchange") { $result = "SUCCESS_KEY_EXCHANGE" }
    elseif ($serverOutput -match "Encrypted Finished") { $result = "SUCCESS_FINISHED" }
    elseif ($serverOutput -match "Decrypted") { $result = "SUCCESS_DECRYPTED" }
    elseif ($serverOutput -match "ECONNRESET") { $result = "ECONNRESET" }
    elseif ($serverOutput -match "bad_certificate") { $result = "BAD_CERT" }
    elseif ($serverOutput -match "Waiting for ClientKeyExchange") { $result = "HANGING" }
    elseif ($serverOutput -match "Client connected") { $result = "CONNECTED_NO_RESPONSE" }
    else { $result = "NO_CONNECTION" }
    
    # Check if game crashed
    $gameRunning = Get-Process -Name FIFA17 -ErrorAction SilentlyContinue
    if (-not $gameRunning) { $result += "_GAME_CRASHED" }
    
    Write-Host "  RESULT: $result" -ForegroundColor $(if ($result -match "SUCCESS") { "Green" } elseif ($result -match "HANGING") { "Yellow" } else { "Red" })
    
    # Log result
    $entry = "=== TEST ${testNum}: $($patch.name) ===`n"
    $entry += "DESC: $($patch.desc)`n"
    $entry += "RESULT: $result`n"
    $entry += "FRIDA: $fridaOutput`n"
    $entry += "SERVER: $($serverOutput.Substring([Math]::Max(0, $serverOutput.Length - 500)))`n"
    $entry += "===`n"
    Add-Content $resultsFile $entry -Encoding UTF8
    
    # Kill game
    Stop-Process -Name FIFA17 -Force -ErrorAction SilentlyContinue
    Start-Sleep 3
}

# Final cleanup
Kill-Everything
Remove-Item "$repoRoot\temp_patch.js" -Force -ErrorAction SilentlyContinue

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ALL TESTS COMPLETE" -ForegroundColor Green
Write-Host "Results saved to batch-results.log" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# Push results
git add batch-results.log
git commit -m "Batch test results $timestamp"
git push 2>&1

Write-Host "Results pushed to git." -ForegroundColor Cyan
