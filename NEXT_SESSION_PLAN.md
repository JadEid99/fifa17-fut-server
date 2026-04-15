# FIFA 17 Private Server — Context Transfer (End of Day 6)

## CURRENT STATUS

### What works:
- Full connection pipeline: DNS → TLS → Redirector → Main Server → PreAuth ✅
- TDF encoding: PreAuth (325/376 bytes), CreateAccount (3 fields), FetchClientConfig (4 fields) ✅
- All 16 DLL patches applied successfully ✅
- OSDK screen can be shown (0x8c6=1) or hidden (0x8c6=0) at will ✅
- PreAuth handler runs, calls FUN_146e1c3f0 which initializes loginSM ✅
- FUN_146e19720 (Login start) called during PreAuth, returns OK ✅

### The blocker:
After CreateAccount, the game sends **Logout** instead of **Login**.
The Login RPC was queued during PreAuth by FUN_146e19720, but the game
cancels it and sends Logout before it fires.

### What we tried to trigger Login (all failed):
1. State transition (1,3) from cave → triggers OSDK screen (wrong transition)
2. FUN_146e19720 from background thread → too late, game already sent Logout
3. FUN_146e19720 from cave (offset 0x3b6) → crash (wrong offset, all zeros)
4. FUN_146e19720 from cave (offset 0x1DB0) → no crash but no effect (one-shot, already called)
5. Trampoline with fake response object → crash (handler accesses response vtable)
6. OSDK web view approach → no HTTP requests made (screen stuck on TOS loading)

### Key Ghidra findings:
- CreateAccount handler (FUN_146e151d0) reads response[0x10-0x13]:
  - +0x10 = UID byte (non-zero = account exists)
  - +0x13 = persona creation flag (non-zero = show OSDK screen)
- State transition (1,3) = OSDK screen trigger (persona creation path)
- FUN_146e1c3f0 = Login type processor (called by PreAuth, initializes loginSM)
- FUN_146e19720 = Login start (one-shot, checks loginSM+0x18 != 0)
- loginSM = preAuthParam1 + 0x1DB0 (NOT 0x3b6 — pointer arithmetic on longlong*)
- OSDK screen is a Nucleus web view (UIWebViewWidget) but it doesn't load
  until TOS responses are processed
- The web view loads from nucleusConnect URL (http://127.0.0.1:8080)
  but no HTTP requests were observed — TOS processing blocks it

### OSDK screen flow:
1. CreateAccount → cave sets 0x8c6=1, calls transition (1,3)
2. Game sends GetLegalDocsInfo (0xF2), GetTOS (0xF6), GetPrivacy (0x2F)
3. Server responds with TOS content
4. Screen stays in loading state (TOS responses not processed correctly?)
5. Web view never loads (no HTTP requests to port 8080)

## NEXT STEPS (Priority order)

### Option A: Fix TOS response decoding
The OSDK screen is stuck because TOS responses aren't decoded.
If we fix the TOS TDF format, the screen would process them,
load the web view, and we could serve an auto-completing HTML page.
Need to investigate what fields the TOS decoder expects.

### Option B: Find the correct state transition to Login
We know (1,3) = OSDK screen. There might be other values that
advance to Login directly. Need to reverse-engineer the state
machine's transition table in Ghidra.

### Option C: Patch the Logout sender
Instead of preventing Logout, intercept the Logout RPC and
convert it to a Login RPC. Or patch the function that sends
Logout to send Login instead.

### Option D: Re-examine why Login RPC doesn't fire
FUN_146e19720 was called during PreAuth and queued a Login job.
But the job never fires. Maybe it's waiting for a condition
that's never met, or it's canceled by the Logout.

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script (v35: Login init check)
- `batch_test_lsx.ps1` — Automated test (builds DLL, starts server, launches game)
- `frida_test.ps1` — Automated Frida test
- `batch-results.log` — Auto-logged server + DLL output

## BUILD & TEST
```
# Pull first, then test:
git pull
.\batch_test_lsx.ps1       # No Frida
.\frida_test.ps1           # With Frida tracing
```
