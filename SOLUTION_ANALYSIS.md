# FIFA 17 Private Server — New Solution Analysis

## Root Cause (Confirmed via Ghidra)

The CreateAccount handler `FUN_146e151d0` reads from the response object at offsets:
- `+0x10` → stored at state+0x8c0 (UID byte)
- `+0x11` → stored at state+0x8c1
- `+0x12` → stored at state+0x8c5
- `+0x13` → checked: if non-zero AND vtable+0x40 returns 0, triggers state (1,3)

The TDF decoder for CreateAccountResponse NEVER populates these offsets. This is confirmed.

## Why Previous Approaches Failed

1. **TDF response variations**: The decoder reads 3 fields but maps them to different offsets than +0x10-0x13. No TDF body will fix this.
2. **State transition (2,1)**: Crashed because the state machine object at index 2 (param_1[3]) may not be initialized at that point in the flow.
3. **DLL Login injection**: Calls FUN_146e1eb70 from wrong thread — RPC queued but never sent.
4. **Wire-level redirect**: Server sees OriginLogin, but game still uses CreateAccountResponse decoder.

## New Approach: Bypass CreateAccount Entirely via Login Type Array

### The Key Discovery

In `FUN_146e1c3f0` (called during PreAuth), the login type array at `loginSM+0x218` is populated from the PreAuth response TDF at offset `+0x120`. If this array has entries, `FUN_146e1dae0` iterates them and calls `FUN_146e1eb70` which sends the actual Login RPC.

**The login type array is EMPTY because our PreAuth response doesn't include login type entries.**

The BF4 emulator works differently — it uses `-authCode noneed` which makes the game skip CreateAccount and send SilentLogin directly. But BF4's architecture is different from FIFA 17's.

### Proposed Solution: DLL-Only Approach (No Frida)

Instead of trying to fix the TDF decoder or redirect commands, we should:

1. **Patch the CreateAccount handler (`FUN_146e151d0`) in the DLL** to:
   - Force `param_3 = 0` (success path)
   - Write the correct values to the state object (+0x8c0=1, +0x8c1=0, +0x8c2=0)
   - Skip the `cVar2` check (vtable+0x40 call)
   - Skip `FUN_146e00f40` (OSDK screen)
   - Call the state transition with (2,1) instead of (1,3) — BUT on the correct state machine object

2. **The critical fix for (2,1)**: The crash happened because:
   - The state machine object `param_1[1]` is the state machine
   - `(**(code **)(*(longlong *)param_1[1] + 8))((longlong *)param_1[1], 2, 1)` calls the transition
   - State 2 = `sm[3]` in the transition function. If sm[3] is NULL, crash.
   - We need to verify sm[3] is valid before calling (2,1)
   - Alternative: call (1,3) but NOP the OSDK screen, then immediately trigger (2,1) from the state 1 handler's context

3. **Alternative: Populate the login type array directly from the DLL**
   - After PreAuth completes and `g_preAuthParam1` is saved
   - Write a fake login type entry into `loginSM+0x218`
   - Call `FUN_146e1dae0` on the game's main thread (not DLL bg thread)
   - This would make the game send Login/SilentLogin natively

## BREAKTHROUGH: v57 Login Type Injection

v57 achieved what no previous version could:
- `FUN_146e1eb70` was called for the FIRST TIME EVER
- `FUN_146e1dae0` returned 1 for the FIRST TIME EVER  
- Login RPC was queued (returned job handle 0x99cd801)
- BUT: the Login job was queued as async and the connection died before it could fire

The Login RPC never appeared on the wire because CreateAccount still runs after PreAuth,
and the game disconnects after CreateAccount regardless of state machine state.

## Origin IPC Simulator — The Real Solution

### Discovery from Ghidra

The Origin SDK communicates via **TCP sockets** (not shared memory or named pipes):
- `FUN_14712ca40` creates a TCP socket: `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`
- Connects to `127.0.0.1` on a port stored at `originSDK+0x35c`
- Exchanges XML messages via `Origin::OriginSDK::SendXml`
- Auth code requests go through `FUN_1470e67f0` → `FUN_1470e1ed0` (15s timeout)

### How It Works

1. Game calls `FUN_1470db3c0` (RequestAuthCode)
2. If Origin SDK is available (`DAT_144b7c7a0 != 0`), it calls `FUN_1470e3560()` to get the SDK object
3. SDK object calls `FUN_1470e67f0` (SendXml) which builds an XML request
4. XML is sent via TCP to Origin client on localhost
5. Origin responds with XML containing the auth code
6. Game uses auth code to send SilentLogin (not CreateAccount!)

### Plan

1. Build a lightweight TCP server that listens on a known port
2. Responds to Origin SDK XML requests with fake auth codes
3. Patch the Origin SDK port (`originSDK+0x35c`) to point to our server
4. Set `DAT_144b7c7a0` to a valid SDK object (already done in DLL)
5. The game should then get a "real" auth code and send SilentLogin directly

## BREAKTHROUGH: OSDK Completion Bypass (Frida v54)

### The Discovery

From Ghidra analysis of `FUN_146e15320` (the OSDK completion handler):
```c
void FUN_146e15320(longlong *param_1, ...) {
    (**(code **)(*param_1 + 0xa8))();  // cleanup
    (**(code **)(*(longlong *)param_1[1] + 8))((longlong *)param_1[1], 0, 0xFFFFFFFF);  // state (0, -1)
    // ... callback dispatch
}
```

When the OSDK account creation screen completes, it calls state transition **(0, -1)**.
This returns the state machine to state 0, which should trigger the Login flow.

### Why (2,1) Crashed

State transition (2,1) crashed because `sm[3]` (state 2 handler) is likely not initialized.
The state machine may only have states 0 and 1. State 2 doesn't exist.

### The Fix (Frida v54)

1. Let CreateAccount handler run with +0x10=1, +0x13=1 → triggers state (1,3)
2. NOP FUN_146e00f40 → prevents OSDK screen from loading
3. After handler returns, call vtable+0xa8 cleanup on handler object
4. Call state transition (0, 0xFFFFFFFF) → simulates OSDK completion
5. State machine returns to state 0 → should trigger Login flow

### Immediate Next Steps

1. **Test Frida v54** — run `frida_test.ps1` and check if state (0, -1) advances to Login
2. **If Login fires** — server already has working Login handler, should get session
3. **If Login doesn't fire** — the state 0 handler may need additional context
   - Check what state 0's onEnter does with param (0xFFFFFFFF)
   - May need to call FUN_146e1dae0 (login check) manually after state transition
4. **Alternative: Populate login type array** — find the TDF field in PreAuth response
   that maps to offset 0x120 (login types). Need raw binary access to read the
   TDF member info table at 0x144874a90.
