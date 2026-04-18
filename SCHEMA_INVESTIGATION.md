# FIFA 17 PreAuthResponse Schema Investigation — April 18, 2026

## Objective
Find the TDF tag that populates the login types array at `loginSM+0x218/+0x220`.
Without login types, `FUN_146e1dae0` (LoginCheck) returns 0, `FUN_146e19b30`
(LoginFallback) fires, and the game sends Logout after 30 seconds.

## Previous Assumption (WRONG)
All 23 previous tests assumed there was an **unknown TDF tag** in the
PreAuthResponse that maps to a field at response object offset `+0x120`.
The theory was: if we find this tag and send it in our server's PreAuth
response, the game would populate the login types array naturally.

Two schema dump attempts on April 17 failed:
- `frida_dump_preauth_schema.js` — read member info table at wrong address,
  found string pointers but not tag encodings
- `frida_decode_preauth_tags.js` — scanned for TDF tag byte patterns,
  got nonsense tags (HSR', RHX!, ION.) because bytes were in wrong order

Both attempts were abandoned and the project pivoted to direct injection
(Frida tests 1-23), all of which failed.

## What We Did Today

### Test Run 1: Frida script crash
- **Script**: `frida_dump_preauth_members.js` v1 (5 approaches)
- **Result**: `TypeError: not a function` at line 19
- **Cause**: `Module.findBaseAddress` not available in Frida 17.9.1 attach mode
- **Fix**: Try `Process.enumerateModules()[0].base` as fallback

### Test Run 2: Hooks fired, memory reads worked, no schema found
- **Script**: v1 with base address fix
- **Result**: PreAuth handler hooked, LoginTypesProcessor hooked, response
  object dumped. Binary scan found zero Taggi-format chains.
- **Key data**: `resp+0x120` vtable = `0x143889d10`, type code = `0x0A`,
  login types list start/end = `0x0/0x0` (empty)
- **Finding**: The Taggi-format entries aren't in the `.rdata` section at
  the scanned offsets. FIFA 17 uses Denuvo which may encrypt/relocate sections.

### Test Run 3: Raw hex dump of member info table (256 bytes)
- **Script**: v3 — brute force dump of 1024 bytes at table address + string scan
- **Result**: Found field name strings at the table pointer region (`0x4874a90`):
  ```
  @008: "authenticationSource"
  @038: "componentIds"
  @068: "clientId"
  @098: "config"
  @0c8: "entitlementSource"
  @0f8: "serviceName"
  ```
- **Key discovery**: Each entry is 48 bytes (0x30). Tag bytes at `+0x21..+0x23`
  in REVERSED byte order. Field offset at `+0x28` as u16 LE.
- **Decoded tags** (reversed bytes):
  - `authenticationSource` → ASRC (offset 0x1D8) ✓
  - `componentIds` → CIDS (offset 0x070) ✓
  - `clientId` → CLID (offset 0x058) — FIFA 17-specific, not in Blaze3SDK
  - `config` → CONF (offset 0x0B8) ✓
  - `entitlementSource` → ESRC (offset 0x228) ✓
- **Problem**: Only 256 bytes captured = 5 entries. Need all 14.

### Test Run 4: Full 672-byte dump (all 14 entries)
- **Script**: v3.1 — increased read to 672 bytes
- **Result**: ALL 14 field names and tags decoded:

```
[ 0] ASRC  offset=0x1d8  authenticationSource
[ 1] CIDS  offset=0x070  componentIds
[ 2] CLID  offset=0x058  clientId
[ 3] CONF  offset=0x0b8  config
[ 4] ESRC  offset=0x228  entitlementSource
[ 5] INST  offset=0x040  serviceName
[ 6] MAID  offset=0x240  machineId
[ 7] MINR  offset=0x220  underageSupported
[ 8] NASP  offset=0x1c0  personaNamespace
[ 9] PILD  offset=0x208  legalDocGameIdentifier
[10] PLAT  offset=0x028  platform
[11] QOSS  offset=0x120  qosSettings          <<<< THE FIELD AT +0x120
[12] RSRC  offset=0x1f0  registrationSource
[13] SVER  offset=0x010  serverVersion
```

## THE BREAKTHROUGH

**The field at response offset `+0x120` is QOSS (qosSettings).**

This is NOT a separate "login types" field. It's the standard QoS settings
struct that we already send. The PreAuth handler passes `resp+0x120` (QOSS)
to `FUN_146e1c3f0` (LoginTypesProcessor), which then calls `FUN_146e1c1f0`
to populate login types from INTERNAL state — not from the QOSS TDF data.

### Verification
- QosConfigInfo has exactly 4 registered TDF fields: BWPS, LNP, LTPS, SVID
  (confirmed from Ghidra: `_DAT_14486e758 = 4`)
- These are the same 4 fields we already send in our QOSS struct
- There is NO 5th field for login types in QosConfigInfo
- The login types at `loginSM+0x218/+0x220` come from `FUN_146e1c1f0`
  which reads `loginSM+0xC8`

## NEW ROOT CAUSE

`FUN_146e1c1f0` (called inside LoginTypesProcessor) does this:

```c
plVar1 = (longlong *)(param_1 + 0xb8);   // a TDF list object
(**(code **)(*plVar1 + 0xa8))(plVar1);    // clear the list

if (*(longlong *)(param_1 + 200) != 0) {  // param_1+200 = loginSM+0xC8
    // ... populate login type entries ...
    plVar7 = *(longlong **)(param_1 + 0xe0);
}
```

If `loginSM+0xC8 == 0`, the entire login type population is SKIPPED.
The list stays empty. LoginCheck returns 0. Logout fires.

**`loginSM+0xC8` is the actual root cause.** It's zero because whatever
game logic should populate it hasn't run or hasn't been triggered correctly
in our emulated environment.

## What loginSM+0xC8 Likely Is

From the code pattern in `FUN_146e1c1f0`:
```c
(int)((*(longlong *)(param_1 + 200) - *(longlong *)(lVar5 + 0x30)) / 0x30) == 2
```

This checks if there are exactly **2 entries** in an array. The array
starts at `*(lVar5 + 0x30)` and `loginSM+0xC8` points to the end.
Each entry is `0x30` (48) bytes. The check `== 2` means the game
expects exactly 2 login type configurations.

`loginSM+0xE0` is then read as a pointer to the current entry.

This is likely a **LoginTypeConfig array** that's populated during
BlazeSDK initialization — possibly from the CIDS (component IDs) list
or from the FetchClientConfig responses.

## What's Different From Previous Attempts

| Aspect | Previous (23 tests) | Current |
|--------|---------------------|---------|
| Assumed cause | Missing TDF tag in PreAuth | loginSM+0xC8 == 0 |
| Approach | Add TDF field / inject into array | Find what populates +0xC8 |
| Target | PreAuth response encoding | BlazeSDK internal initialization |
| Scope | Server-side TDF | Client-side game logic |

None of the 23 previous tests examined `loginSM+0xC8` or `FUN_146e1c1f0`.
All assumed the problem was in the TDF wire format.

## Test Run 5 (v4): loginSM+0xC8 dump — CRITICAL FINDING

- **Script**: v4 — hooks LoginTypesProcessor + FUN_146e1c1f0, dumps loginSM state
- **Result**: `loginSM+0xC8 = 0x14486b590` — **NOT ZERO!**
- `FUN_146e1c1f0` entered and returned normally (no crash)
- `loginSM+0xE0 = 0x3eb69ec0` (valid heap pointer)
- `parent+0x53f = 1` (flag is set correctly)
- `parent+0x53c = 3659` (transport type)
- `loginSM+0x1A0 = 0`
- Login types array at `+0x218/+0x220` still both zero after function returns

### Revised Analysis

`loginSM+0xC8` is NOT the blocker. The condition in `FUN_146e1c1f0` PASSES
(the function runs without crashing, meaning `plVar7` was set). The function
populates entries in the list at `loginSM+0xB8`.

But `loginSM+0x218/+0x220` (the login types array that LoginCheck reads)
is STILL zero. These pointers come from the TDF copy:

```c
(**(code **)(*param_2 + 0x18))(param_2, param_1 + 0x1b8, &local_res8);
```

This copies the QOSS struct data to `loginSM+0x1b8`. The array pointers at
`+0x218/+0x220` are at internal offset `+0x60/+0x68` within the copied QOSS
data. Since the QOSS object's internal list at `resp+0x120+0x60` is empty
(confirmed: both pointers are 0x0), the copy produces empty pointers.

### The REAL Root Cause (Revised)

The QOSS C++ object has an internal list at offset `+0x60` that is NOT
populated by any of the 4 registered TDF fields (BWPS, LNP, LTPS, SVID).
This list is part of the C++ class but has no TDF tag — it's populated by
internal game logic, likely during QOSS object construction or by a
post-decode callback.

In a real EA server environment, the QOSS object would be constructed
server-side with this internal list populated, then serialized to TDF.
The client deserializes it and the list data comes through as part of
the QOSS struct's binary representation.

**The issue is that our TDF encoder doesn't know about this internal list.**
When we encode QOSS with BWPS+LNP+LTPS+SVID, the resulting binary doesn't
include the list data at offset +0x60. The game's TDF decoder reads our
QOSS data, populates the 4 named fields, but the internal list stays
at its default-constructed empty state.

### What This Means

The Login job is queued successfully (LoginSender returns non-zero, job handle
persists at T+3s). But the RPC never appears on the wire. The job scheduler
doesn't dispatch it before the 30-second Logout timer fires.

Possible causes:
1. The job scheduler runs on the game's main thread during the online tick.
   The DLL's Patch 14 forces connState=0 continuously, which might prevent
   the online tick from processing the job queue.
2. The Logout timer (30s from LoginFallback) fires before the job scheduler
   gets to the Login job. Our replaced LoginCheck returns 1 (preventing
   LoginFallback), but the timer might have already been started by a
   previous call.
3. The job has a dependency on another job (QoS) that hasn't completed.

## BREAKTHROUGH: SilentLogin RPC on the Wire (v7.2)

**Date:** April 18, 2026
**Result:** The server received a SilentLogin RPC from the game client for the FIRST TIME EVER.

```
[Main] S1: comp=0x0001 cmd=0x0032 len=42 msgId=100
[Main] S1: -> Auth cmd=0x32 (SilentLogin)
```

**How it was achieved:**
- Frida v7 replaces LoginCheck (`FUN_146e1dae0`) entirely
- Instead of going through the BlazeSDK's job system (which gets stuck on QoS),
  we build a raw SilentLogin TDF packet in memory and call `ws2_32!send()` directly
  on the Blaze TCP socket (fd=4244, found by hooking `recv()`)
- The packet: 16-byte Blaze header + TDF body with AUTH, PID, TYPE fields
- `send()` returned 58 (all bytes sent successfully)
- Server received it, decoded the TDF, and sent a Login response

**What the server log shows (full sequence):**
```
PreAuth (comp=0x0009 cmd=0x0007) → response sent
SilentLogin (comp=0x0001 cmd=0x0032 len=42 msgId=100) → LOGIN RESPONSE SENT  ← NEW!
Ping → pong
FetchClientConfig × 6 → responses sent
Ping × 2
Logout (comp=0x0001 cmd=0x0046)
Ping × 2
```

**Why the game still sends Logout:**
The SilentLogin was sent with msgId=100 (arbitrary). The BlazeSDK's RPC framework
dispatches responses by matching msgId to pending requests. Since no request with
msgId=100 was registered through the framework, the response is silently dropped.
The game doesn't know it received a Login response.

## Next Steps

### Option A: Make the game process the Login response (highest probability)

The server sends the Login response with msgId=100. The game's response dispatcher
(`FUN_146db5a60`) looks up msgId=100 in the pending request table. Finding nothing,
it drops the response.

**Fix:** After sending the raw SilentLogin, also send the 4 post-login notifications
from the SERVER side. Notifications don't need msgId matching — they're dispatched
by component+command. The game has registered handlers for:
- `NotifyUserAdded` (comp=0x7802, cmd=0x0002)
- `UserSessionExtendedDataUpdate` (comp=0x7802, cmd=0x0001)

If the server sends these notifications with proper session data (BUID, KEY, PDTL),
the game's notification handlers will process them and update internal session state.
Combined with the DLL's patches that force `connState=0` and `BlazeHub+0x53f=1`,
this might be enough to transition the game to the authenticated state.

**Implementation:**
1. Modify `server.mjs` to detect the SilentLogin RPC (comp=0x0001, cmd=0x0032)
2. After sending the Login response, send the 4 notifications on timed delays:
   - T+300ms: NotifyUserAdded (comp=0x7802, cmd=0x0002, type=notification)
   - T+500ms: UserSessionExtendedDataUpdate (comp=0x7802, cmd=0x0001, type=notification)
   - T+700ms: UserUpdated (comp=0x7802, cmd=0x0005, type=notification)
3. Use the BF4 emulator's notification format as the template

### Option B: Register a fake pending request in the BlazeSDK

Use Frida to write a fake entry in the BlazeSDK's pending request table for msgId=100.
When the Login response arrives, the dispatcher finds the entry and calls the callback.
This is more complex but would make the game process the response natively.

### Option C: Use the game's own msgId

Instead of msgId=100, use the NEXT msgId the game would naturally use. The game's
msgId counter is at a known location. Read it, use that value, and the response
might match a pending request. But this is risky — the pending request might not
exist for a Login command.

### Recommendation

**Option A is the best path.** We already proved that notifications are dispatched
by component+command without msgId matching (from the Ghidra analysis of
`FUN_146db5a60`). The server just needs to send the right notifications after
the Login response. This is a server-side change — no more Frida modifications needed.


