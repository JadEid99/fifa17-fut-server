# FIFA 17 Private Server — Context Transfer (End of Day 6, Final)

## CURRENT STATUS

### Pipeline:
```
DNS ✅ → TLS ✅ → Redirector ✅ → Main Server ✅ → PreAuth ✅ → FetchClientConfig ✅ → [Login ❌] → Logout → disconnect
```

### What works:
- Full connection pipeline through FetchClientConfig ✅
- CreateAccount SKIPPED (Patch 3 returns error) ✅
- Age check BYPASSED (Patch 18) ✅
- Login job CREATED during PreAuth (confirmed by Frida v40/v41) ✅
- Login init chain: FUN_146e1c3f0 → FUN_146e19720 → FUN_1478aa0f0 all fire ✅

### THE EXACT BLOCKER (identified by Frida v40/v41):
The Login job is created but `FUN_146e1dae0` returns false because the
**login type array** at `loginSM + 0x218` to `loginSM + 0x220` is empty.

`FUN_146e1dae0` iterates over this array and calls `FUN_146e1eb70` for each
entry. `FUN_146e1eb70` is what actually sends the Login RPC (calls
`FUN_1478aa320` with the auth token). But with an empty array, the loop
never executes and no Login is sent.

The array is populated by `FUN_146e1c3f0` from the PreAuth response at
`param_2 + 0x120`. The PreAuth TDF decoder reads 325 of 376 bytes but
doesn't populate the login type list.

### ROOT CAUSE:
The PreAuth response TDF doesn't include the login type data that populates
the `loginSM + 0x218` array. This array should contain entries with auth
tokens for each supported login type (Login, SilentLogin, ExpressLogin).

### NEXT STEPS (Priority order):

1. **Find what TDF fields populate the login type array**
   - The array is filled by `(**(code **)(*param_2 + 0x18))(param_2, param_1 + 0x1b8, &local_res8)`
     inside FUN_146e1c3f0. `param_2` is the decoded PreAuth response at offset +0x120.
   - Need to find what TDF field in the PreAuth response maps to this list.
   - Use Frida to hook the vtable+0x18 call and see what it reads.

2. **Alternatively: populate the array manually from the DLL**
   - Write a fake login type entry at loginSM + 0x218
   - Each entry is 0x20 bytes, need to reverse-engineer the structure
   - The entry needs an auth token string and a login type identifier

3. **Alternatively: call FUN_146e1eb70 directly from the DLL**
   - Skip the array iteration and call the Login sender directly
   - Need: loginSM, a fake param_2 entry, param_3 (auth token), param_4=1

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches (19 patches)
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script (v41)
- `batch_test_lsx.ps1` — Automated test
- `batch-results.log` — Auto-logged output

## PATCHES (20 total, 18 active)
| # | What | Status |
|---|------|--------|
| 1 | Cert bypass | ✅ |
| 2 | Origin SDK check | ✅ |
| 3 | Auth code → ERROR (skip CreateAccount) | ✅ MODIFIED |
| 4 | Auth flag | ✅ |
| 5+6 | IsLoggedIn | ✅ |
| 7 | SDK gate + vtable | ✅ |
| 8 | PreAuth handler (XOR R8D) | ✅ |
| 9 | PreAuth completion (RET) | ✅ |
| 10 | OriginCheckOnline | ✅ |
| 11 | GetGameVersion | ✅ |
| 12 | Version compare | ✅ |
| 13 | OSDK functions | ✅ |
| 14 | connState force | ✅ |
| 15 | BlazeHub+0x53f force | ✅ |
| 16 | CreateAccount handler | ❌ DISABLED |
| 17 | OSDK Logout NOP | ✅ |
| 18 | Age check (EARLY) | ✅ |
| 19 | Login check return 1 (EARLY) | ✅ |

## BUILD & TEST
```
git pull
.\batch_test_lsx.ps1       # No Frida
.\frida_test.ps1           # With Frida
```
