# FIFA 17 Private Server — Context Transfer (End of Day 6)

## OBJECTIVE
Get past the authentication stage so the game sends Login/PostAuth and reaches the online menu.

## CURRENT STATE
The game connects, does PreAuth + FetchClientConfig, then either:
- Sends CreateAccount → Logout (with fake auth code from Patch 3)
- Sends just Logout (without auth code)

Neither path reaches Login. We need the game to send Login (cmd=0x28/0x32/0x98).

## WHAT WORKS
- Full TLS/Blaze connection pipeline ✅
- PreAuth response decoded (325/376 bytes) ✅
- FetchClientConfig responses decoded ✅
- 19+ DLL patches applied successfully ✅
- CreateAccount TDF encoding fixed (3 fields read) ✅
- OSDK screen can be shown/hidden at will ✅

## THE CORE PROBLEM
The CreateAccount response TDF decoder NEVER populates the response object (confirmed by Frida v39: all bytes at +0x10-0x13 are zero regardless of what we send). The original handler crashes if we let it run. Our bypass cave sets state bytes but the caller sends Logout anyway.

The Login RPC IS queued during PreAuth (confirmed by Frida v40/v41) but never fires because the login type array at loginSM+0x218 is empty (confirmed by Frida v42/v44). The array is populated from the PreAuth response but the TDF decoder doesn't fill it.

## APPROACHES TRIED AND FAILED
1. Fix CreateAccount TDF encoding (many field combinations) — decoder never populates response
2. Bypass cave with state bytes (0x8c0=1, 0x8c6=0) — Logout still sent
3. State transition (1,3) from cave — triggers OSDK screen
4. Call FUN_146e19720 from cave/bg thread — one-shot, already called
5. Reset loginSM+0x18 and re-call — no effect (queued but never fires)
6. OSDK web view approach — web view never loads (empty page array)
7. Proactive SilentLogin notifications — game ignores them
8. Error response (0x0F exists) — game still sends Logout
9. Don't respond to Logout — game disconnects client-side anyway
10. Skip CreateAccount (Patch 3 returns error) — age check, then Logout
11. Bypass age check (Patch 18) — still Logout (no auth credentials)
12. Force login check return 1 (Patch 19) — still Logout
13. Inject fake login type entry + call FUN_146e1eb70 — returns success but RPC queued on wrong thread
14. Raw SilentLogin on separate connection — server works, game doesn't see it
15. Change CreateAccount to OriginLogin (Patch 20) — patch applied but wrong call site

## KEY FINDINGS FROM FRIDA
- v34: TDF decoder reads 3 fields for CreateAccount, 9 for PreAuth, 4 for FetchClientConfig
- v35: FUN_146e1c3f0 IS called during PreAuth, loginSM+0x08=BlazeHub, 0x53f=1
- v39: CreateAccount response object +0x10-0x13 always zero (TDF decoder broken)
- v40: Login job IS created (FUN_1478aa0f0 returns valid job), login type=0
- v41: FUN_146e1dae0 returns false (login type array empty), FUN_146e19b30 (alt path) called
- v42: loginSM+0x218/+0x220 = 0/0 (empty array), +0xE0 has login type entry, +0x18 has job
- v44: PreAuth response +0xb8 has vtables but empty list data, +0x120 has config data

## MOST PROMISING NEXT STEPS

### Option A: Patch ALL CreateAccount send sites
FUN_146e15070 was patched but the game uses a different call site.
Lines 4254759 and 5512261 in Ghidra also send command 10.
Find those functions and patch them too. Or find the ACTUAL function
that sends the CreateAccount we see in the server log.

### Option B: Patch FUN_146dab760 directly
Instead of patching each caller, patch FUN_146dab760 (the RPC builder)
to change command 10 to 0x98 whenever it's called. This catches ALL
CreateAccount sends regardless of which function calls it.

### Option C: Populate the login type array from the PreAuth response
The array at loginSM+0x218 is populated by a vtable+0x18 call on the
PreAuth response's login config object at +0x120. If we can figure out
what TDF field populates this, we can add it to our PreAuth response
and the Login flow would work naturally.

### Option D: Call FUN_146e1eb70 from the game's main thread
FUN_146e1eb70 returns success when called from the DLL bg thread,
but the RPC is queued and never sent (wrong thread). If we call it
from a hook on the game's main thread (e.g., hook a FetchClientConfig
handler), the RPC would be processed on the right thread.

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script
- `batch_test_lsx.ps1` / `frida_test.ps1` — Test scripts
- `batch-results.log` — Auto-logged output
- Ghidra export: `/Users/jadeid/Downloads/ghidra/FIFA17_dumped.bin.c` (6.5M lines)

## KEY ADDRESSES (no ASLR, base=0x140000000)
| Address | Function | Purpose |
|---------|----------|---------|
| 0x146e1cf10 | PreAuth handler | PATCHED: XOR R8D trampoline |
| 0x146e151d0 | CreateAccount handler | PATCHED: bypass cave |
| 0x146e15070 | CreateAccount sender | PATCHED: cmd 0x0A→0x98 (wrong site) |
| 0x146e1c3f0 | Login type processor | Called by PreAuth, inits loginSM |
| 0x146e19720 | Login start | Creates login job (one-shot) |
| 0x146e1dae0 | Login check | Returns false (empty array) |
| 0x146e1eb70 | Login RPC sender | Sends auth token via FUN_1478aa320 |
| 0x146df0e80 | RPC send | Generic Blaze RPC dispatcher |
| 0x146dab760 | RPC builder | Builds RPC with component+command |
| 0x14717d5d0 | Age check | Checks DOB, shows underage error |
| 0x1472d62a0 | OSDK Logout | UI-level logout function |
| 0x1470db3c0 | Auth code provider | PATCHED: fake auth code |

## BUILD & TEST
```
git pull
.\batch_test_lsx.ps1       # No Frida
.\frida_test.ps1           # With Frida
```
