# FIFA 17 Private Server — Context Transfer (End of Day 6, Late)

## CURRENT STATUS — SIGNIFICANT PROGRESS

### What works:
- Full connection: DNS → TLS → Redirector → Main Server → PreAuth → FetchClientConfig ✅
- CreateAccount SKIPPED entirely (Patch 3 returns error, no auth code) ✅
- Age check BYPASSED (Patch 18: FUN_14717d5d0 → RET) ✅
- OSDK screen eliminated ✅
- No crashes ✅

### Current flow:
```
PreAuth → Ping → FetchClientConfig ×6 → Ping → Logout → disconnect
```

### The remaining blocker:
Game sends Logout after FetchClientConfig. Login RPC never fires.
FUN_146e19720 (Login start) was called during PreAuth (confirmed by Frida v35)
but the Login RPC job never sends the actual Login command.

### Key theory to investigate:
The PreAuth handler's success path reads config values from the decoded
PreAuth response (pingPeriod, defaultRequestTimeout, connIdleTimeout, etc.)
using vtable+0x58 and vtable+0x50 calls. If these fail (because the TDF
decoder doesn't populate the response correctly), the handler might exit
before reaching FUN_146e1c3f0 (Login type processor).

Need to verify: does FUN_146e1c3f0 actually get called? Frida v35 showed
it does, but that was with the old Patch 3 (fake auth code). With the new
Patch 3 (error return), the flow might be different.

## PATCHES (Current State)

| # | Target | Status | What |
|---|--------|--------|------|
| 1 | Cert verification | ✅ Active | JNZ→JMP |
| 2 | Origin SDK check | ✅ Active | Always true |
| 3 | FUN_1470db3c0 | ✅ MODIFIED | Returns ERROR (no auth code) — prevents CreateAccount |
| 4 | Auth flag | ✅ Active | [RBX+0x2061]=1 |
| 5+6 | IsLoggedIn | ✅ Active | Always true |
| 7 | SDK gate + vtable | ✅ Active | Return 1 |
| 8 | PreAuth handler | ✅ Active | XOR R8D trampoline (success path) |
| 9 | PreAuth completion | ✅ Active | Immediate RET |
| 10 | OriginCheckOnline | ✅ Active | Always online |
| 11 | GetGameVersion | ✅ Active | Return 0 |
| 12 | Version compare | ✅ Active | Always match |
| 13 | OSDK functions | ✅ Active | Return 0 (delayed) |
| 14 | connState | ✅ Active | Force 0 continuously |
| 15 | BlazeHub+0x53f | ✅ Active | Force 1 continuously |
| 16 | CreateAccount handler | ❌ DISABLED | Not needed (CreateAccount skipped) |
| 17 | OSDK Logout | ✅ Active | FUN_1472d62a0 → RET |
| 18 | Age check | ✅ Active | FUN_14717d5d0 → RET |

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script
- `batch_test_lsx.ps1` — Automated test
- `batch-results.log` — Auto-logged output

## NEXT SESSION PRIORITIES

1. **Verify FUN_146e1c3f0 is called** with new Patch 3 (error return)
   - Use Frida to hook FUN_146e1c3f0 and FUN_146e19720
   - If not called, the PreAuth handler is exiting early

2. **If FUN_146e1c3f0 IS called but Login doesn't fire:**
   - The Login job might be waiting for a condition
   - Check if the QoS/Login job callback (LAB_146e1d730) fires
   - The job has a 7000ms timeout — check if it times out

3. **If FUN_146e1c3f0 is NOT called:**
   - The PreAuth handler exits early due to config read failures
   - Need to fix the PreAuth response TDF to include all required fields
   - Or patch the handler to skip the config reads

## BUILD & TEST
```
git pull
.\batch_test_lsx.ps1       # No Frida
.\frida_test.ps1           # With Frida tracing
```
