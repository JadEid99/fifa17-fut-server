# Origin ChallengeResponse Format Tester
# Tests formats 0-5 consecutively, 25s each, logs results

$repoRoot = $PSScriptRoot
$gameDir = "D:\Games\FIFA 17"
$gameExe = "$gameDir\FIFA17.exe"
$logFile = "$gameDir\fifa17_ssl_bypass.log"
$resultsFile = "$repoRoot\origin-format-results.log"

# Build DLL first
$vcvars = ""
if (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat") {
    $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
}
Write-Host "[BUILD] Compiling DLL..." -ForegroundColor Yellow
cmd /c "`"$vcvars`" && cd /d `"$repoRoot\dll-proxy`" && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib 2>&1" | Out-Null
Copy-Item "$repoRoot\dll-proxy\dinput8.dll" "$gameDir\dinput8.dll" -Force
Copy-Item "$repoRoot\commandline.txt" "$gameDir\commandline.txt" -Force

$allResults = ""

$formats = @(2, 0, 1, 3, 4, 5)  # Test silent first, then others
foreach ($fmt in $formats) {
    Write-Host "`n=== Testing Challenge Format $fmt ===" -ForegroundColor Cyan
    
    # Kill everything
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Get-Process -Name node -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
    Start-Sleep 3
    Remove-Item $logFile -Force -EA SilentlyContinue
    
    # Start Blaze server
    $blazeJob = Start-Job -ScriptBlock { 
        param($r)
        $env:PREAUTH_VARIANT="full"
        $env:REDIRECT_SECURE="0"
        node --openssl-legacy-provider --security-revert=CVE-2023-46809 "$r\server-standalone\server.mjs" 2>&1 
    } -ArgumentList $repoRoot
    
    # Start Origin IPC server with this format
    $originJob = Start-Job -ScriptBlock { 
        param($r, $f)
        $env:CHALLENGE_FORMAT=$f
        node "$r\server-standalone\origin-ipc-server.mjs" 2>&1 
    } -ArgumentList $repoRoot, $fmt
    Start-Sleep 3
    
    # Launch game
    Write-Host "[GAME] Launching FIFA 17 (format $fmt)..." -ForegroundColor Yellow
    Start-Process $gameExe
    
    # Wait for game to start (max 15s)
    $gameStarted = $false
    for($i=0;$i -lt 15;$i++){
        if(Get-Process -Name FIFA17 -EA SilentlyContinue){$gameStarted=$true;break}
        Start-Sleep 1
    }
    
    if (-not $gameStarted) {
        Write-Host "[RESULT] Format ${fmt} - GAME DID NOT START (hung?)" -ForegroundColor Red
        $allResults += "Format ${fmt} - GAME_NOT_STARTED`n"
        
        # Force kill hung game
        Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
        
        # Collect Origin output
        $originOut = (Receive-Job $originJob 2>&1 | Out-String).Trim()
        $or1 = if($originOut.Length -gt 500){$originOut.Substring($originOut.Length-500)}else{$originOut}
        $allResults += "  Origin: $or1`n`n"
        
        Stop-Job $blazeJob,$originJob -EA SilentlyContinue
        Remove-Job $blazeJob,$originJob -EA SilentlyContinue
        continue
    }
    
    # Game started — wait 25s for connection flow
    Write-Host "[WAIT] Waiting 25s for connection flow..." -ForegroundColor Yellow
    Start-Sleep 25
    
    # Check if game is still running
    $gameAlive = Get-Process -Name FIFA17 -EA SilentlyContinue
    
    # Collect Origin IPC output
    $originOut = (Receive-Job $originJob 2>&1 | Out-String).Trim()
    
    # Classify result
    $result = "UNKNOWN"
    if ($originOut -match "AUTH CODE REQUEST") { $result = "AUTH_CODE_REQUESTED" }
    elseif ($originOut -match "CHALLENGE.*send") { $result = "CHALLENGE_RESPONDED" }
    elseif ($originOut -match "GetProfile") { $result = "GOT_PROFILE" }
    elseif ($originOut -match "GetSetting") { $result = "GOT_SETTING" }
    elseif ($originOut -match "Connected") { $result = "CONNECTED_ONLY" }
    
    if (-not $gameAlive) { $result = "GAME_CRASHED" }
    
    $msgCount = ([regex]::Matches($originOut, '#\d+')).Count
    
    Write-Host "[RESULT] Format ${fmt} - $result (${msgCount} messages)" -ForegroundColor $(if($result -match "AUTH"){"Green"}elseif($result -match "PROFILE|SETTING"){"Yellow"}else{"Red"})
    
    $or1 = if($originOut.Length -gt 1000){$originOut.Substring($originOut.Length-1000)}else{$originOut}
    $allResults += "Format ${fmt} - $result (${msgCount} msgs)`n  Origin: $or1`n`n"
    
    # Cleanup
    Stop-Process -Name FIFA17 -Force -EA SilentlyContinue
    Stop-Job $blazeJob,$originJob -EA SilentlyContinue
    Remove-Job $blazeJob,$originJob -EA SilentlyContinue
}

# Save all results
Set-Content $resultsFile $allResults -Encoding UTF8
Write-Host "`n=== ALL RESULTS ===" -ForegroundColor Cyan
Write-Host $allResults

# Push
git add -A; git commit -m "Origin format test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"; git push 2>&1
Write-Host "Done." -ForegroundColor Cyan
