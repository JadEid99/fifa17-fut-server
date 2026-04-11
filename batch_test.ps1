# Batch v13: Surgical patch inside cert_process
$ErrorActionPreference = "Continue"
$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$resultsFile = "$repoRoot\batch-results.log"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KSB {
    [DllImport("user32.dll")] public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    public const uint KUP = 0x0002;
    public static void Enter() { keybd_event(0x0D,0x1C,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x0D,0x1C,KUP,UIntPtr.Zero); }
    public static void Q() { keybd_event(0x51,0x10,0,UIntPtr.Zero); System.Threading.Thread.Sleep(50); keybd_event(0x51,0x10,KUP,UIntPtr.Zero); }
}
"@
function Focus { $p=Get-Process -Name FIFA17 -EA SilentlyContinue; if($p -and $p.MainWindowHandle -ne [IntPtr]::Zero){[KSB]::SetForegroundWindow($p.MainWindowHandle)|Out-Null;Start-Sleep -Milliseconds 300;return $true};return $false }
function FEnter { if(Focus){[KSB]::Enter()} }
function FQ { if(Focus){[KSB]::Q()} }
function Kill-All { Stop-Process -Name FIFA17 -Force -EA SilentlyContinue; Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue; Start-Sleep 3 }
function Launch-Game { Start-Process $gameExe; for($i=0;$i -lt 30;$i++){if(Get-Process -Name FIFA17 -EA SilentlyContinue){break};Start-Sleep 1}; Start-Sleep 10;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 5;FEnter;Start-Sleep 10;FEnter;Start-Sleep 2 }
function Run-Frida($code) { $tmp="$repoRoot\tf.js"; Set-Content $tmp "var b=Process.getModuleByName('FIFA17.exe').base;`ntry{`n$code`nsend('OK');`n}catch(e){send('ERR:'+e.message);}" -Encoding UTF8; $p=Start-Process -FilePath "frida" -ArgumentList "-n","FIFA17.exe","-l",$tmp -NoNewWindow -PassThru -RedirectStandardOutput "$repoRoot\fo.txt" -RedirectStandardError "$repoRoot\fe.txt"; $p|Wait-Process -Timeout 10 -EA SilentlyContinue; if(!$p.HasExited){$p|Stop-Process -Force}; $o=(Get-Content "$repoRoot\fo.txt" -Raw -EA SilentlyContinue); Remove-Item $tmp,"$repoRoot\fo.txt","$repoRoot\fe.txt" -Force -EA SilentlyContinue; return $o }

# These patches are INSIDE cert_process - they don't break the state machine
# because they only affect the return value, not the state transitions.
$patches = @(
    # P1: Change JNE at +0x61270C2 to JMP (always take success return path)
    # Original: 75 1E (JNE +0x1E to +0x61270E2)
    # Patched: EB 1E (JMP +0x1E to +0x61270E2) - always returns edi=1
    @{ name="P1_JNE_to_JMP_70C2"; desc="cert_process: JNE->JMP at +0x61270C2 (force success return)"
       fresh=$true
       patch='Memory.protect(b.add(0x61270C2),1,"rwx");b.add(0x61270C2).writeU8(0xEB);' },

    # P2: Same but also patch the bAllowAnyCert checks (belt and suspenders)
    @{ name="P2_JMP_70C2_plus_bAllowAnyCert"; desc="cert_process JMP + 3x bAllowAnyCert"
       fresh=$true
       patch=@'
Memory.protect(b.add(0x61270C2),1,"rwx");b.add(0x61270C2).writeU8(0xEB);
Memory.protect(b.add(0x612522d),1,"rwx");b.add(0x612522d).writeU8(0xEB);
Memory.protect(b.add(0x612753d),1,"rwx");b.add(0x612753d).writeU8(0xEB);
Memory.protect(b.add(0x6127c29),1,"rwx");b.add(0x6127c29).writeU8(0xEB);
'@ },

    # P3: Make the cert parser (+0x6138680) return 0 (no error) + JMP at 70C2
    @{ name="P3_cert_parser_ret0_JMP_70C2"; desc="cert parser ret 0 + JMP at 70C2"
       fresh=$true
       patch=@'
Memory.protect(b.add(0x61270C2),1,"rwx");b.add(0x61270C2).writeU8(0xEB);
Memory.protect(b.add(0x6138680),6,"rwx");b.add(0x6138680).writeByteArray([0x31,0xC0,0xC3,0x90,0x90,0x90]);
'@ },

    # P4: JMP at 70C2 + bAllowAnyCert + also patch the JLE in State 3 caller
    @{ name="P4_full_combo"; desc="JMP 70C2 + bAllowAnyCert + NOP JLE in State 3"
       fresh=$true
       patch=@'
Memory.protect(b.add(0x61270C2),1,"rwx");b.add(0x61270C2).writeU8(0xEB);
Memory.protect(b.add(0x612522d),1,"rwx");b.add(0x612522d).writeU8(0xEB);
Memory.protect(b.add(0x612753d),1,"rwx");b.add(0x612753d).writeU8(0xEB);
Memory.protect(b.add(0x6127c29),1,"rwx");b.add(0x6127c29).writeU8(0xEB);
Memory.protect(b.add(0x61262F7),2,"rwx");b.add(0x61262F7).writeByteArray([0x90,0x90]);
'@ },

    # P5: Control - no patches (should get ECONNRESET)
    @{ name="P5_control"; desc="No patches (control)"
       fresh=$true
       patch="send('no patches');" }
)

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Set-Content $resultsFile "=== BATCH v13 ($timestamp) === $($patches.Count) tests`n" -Encoding UTF8
Write-Host "=== BATCH v13 - $($patches.Count) tests ===" -ForegroundColor Cyan

foreach($p in $patches){
    $n = [array]::IndexOf($patches, $p) + 1
    Write-Host "[$n/$($patches.Count)] $($p.name)" -ForegroundColor Yellow
    
    if($p.fresh){ Kill-All; Launch-Game }
    
    Get-Process -Name node -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 1
    $sj=Start-Job -ScriptBlock{param($r);node "$r\server-standalone\server.mjs" 2>&1} -ArgumentList $repoRoot
    Start-Sleep 2
    
    $fo=Run-Frida $p.patch
    Start-Sleep 1; FQ
    Start-Sleep 20
    
    $so=(Receive-Job $sj 2>&1|Out-String).Trim()
    Stop-Job $sj -EA SilentlyContinue;Remove-Job $sj -EA SilentlyContinue
    
    $r="UNKNOWN"
    if($so -match "TIMEOUT: No data"){$r="TIMEOUT_NO_DATA"}
    if($so -match "Phase=.*received"){$r="RECEIVED_DATA"}
    if($so -match "Handshake type: 0x10"){$r="CLIENT_KEY_EXCHANGE"}
    if($so -match "ECONNRESET"){$r="ECONNRESET"}
    if($so -match "bad_certificate"){$r="BAD_CERT"}
    if($so -match "Waiting for ClientKeyExchange" -and $so -notmatch "ECONNRESET" -and $so -notmatch "Disconnected" -and $so -notmatch "TIMEOUT"){$r="HANGING"}
    if($so -eq ""){$r="NO_CONNECTION"}
    if(-not(Get-Process -Name FIFA17 -EA SilentlyContinue)){$r+="+CRASHED"}
    
    $color=switch -Regex($r){"CLIENT_KEY|RECEIVED"{"Green"}"HANGING|TIMEOUT"{"Yellow"}default{"Red"}}
    Write-Host "  -> $r" -ForegroundColor $color
    
    $ss=if($so.Length -gt 500){$so.Substring($so.Length-500)}else{$so}
    Add-Content $resultsFile "[$n] $($p.name) | $r | $($p.desc)`nSERVER: $ss`n" -Encoding UTF8
    
    FEnter; Start-Sleep 2
}

Write-Host "`n=== DONE ===" -ForegroundColor Green
git add batch-results.log;git commit -m "Batch v13 $timestamp";git push 2>&1
