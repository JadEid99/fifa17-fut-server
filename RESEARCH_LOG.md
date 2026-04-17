# FIFA 17 Research Log

This is Kiro's working log. Every observation, experiment, hypothesis, and
result goes here. Keep it append-only so we have full history.

Convention:
- **FACT** = verified by capture / Ghidra / runtime evidence
- **HYPOTHESIS** = reasoned guess, needs testing
- **TEST** = an experiment we are about to run
- **RESULT** = what the experiment showed
- **TODO** = actionable follow-up

---

## Session: April 17, 2026 — Diagnostic Phase Kickoff

### Context
After many sessions of symptomatic fixes, we're switching to forensic
observation. Full context in `SESSION_LOG.md`. Current state: Origin IPC
works, Blaze PreAuth + 6x FetchClientConfig succeed, but the game sends
**Logout (cmd=0x46, empty body)** as its first auth command and disconnects.

---

### FACT: Logout has no TDF body and no RPC registration string
From `FIFA17_dumped.bin.c` grep of Blaze Authentication RPC registrations:
- CreateAccount, Login, LoginResponse, SilentLogin, OriginLogin, Logout,
  LogoutPersona, DeletePersona, ExpressLogin are all listed.
- Every other Auth RPC has a `s_Blaze__Authentication__<Name>` symbol
  and a TDF member info table registered via `FUN_1479ab1e0`.
- **`Logout` has no such registration.** The only `s_Logout_` in the
  binary is at 0x14398ab94, referenced only by `FUN_1472d62a0`
  (UI-layer `LoginAdaptor::Logout`).

**Implication:** Logout is a bare RPC (cmd=0x0046, no body) that the
Blaze SDK knows to send when the UI-layer `LoginAdaptor::Logout` runs.
Matches what the server logs show (`len=0`).

---

### FACT: Login state machine has only 3 sub-state-machines
From `FUN_146e116a0` (LoginStateMachineImpl constructor) at line 3831319:

```c
FUN_146e116a0(plVar1, param_1, param_2, DAT_14487e01d, ...);  // child SM1 @ +0x7
FUN_146e11610(param_1 + 0xa2, ...);                           // child SM2 @ +0xa2
FUN_146e11570(param_1 + 0xac, ...);                           // child SM3 @ +0xac
param_1[1] = plVar1;         // SM1 at index 1
param_1[2] = param_1 + 0xa2; // SM2 at index 2
// index 3 is NOT set — stays 0
param_1[4] = param_1 + 0xac; // SM3 at index 4
```

**Implication:** Past `state 2, reason 1` crash was because the handler
dereferenced `SM[3]`, which is NULL. State indices are sparse: 1, 2, 4.
Don't try to transition to state 3.

---

### FACT: PreAuthResponse TDF has 14 fields
From `FUN_146df6160` at line 3821020:
```c
PTR_PTR_144875630 = (undefined *)&PTR_DAT_144874a90;  // member info table
_DAT_144875638 = 0xe;                                  // count = 14
```

The member info table at `0x144874a90` contains 14 `TdfMemberInfo` entries.
Each entry has: offset, tag, type, flags. This is the definitive schema.

**TODO:** Dump this table at runtime via Frida to get exact tags and
offsets for each of the 14 PreAuthResponse fields.

---

### FACT: Login types are read from PreAuth response offset +0x120
From `FUN_146e1cf10` (PreAuth response handler) line 3834254:
```c
FUN_146e1c3f0(param_1 + 0x3b6, param_2 + 0x120, &local_40, local_60);
```

`param_2` is the decoded PreAuth response. `param_2 + 0x120` is the
LoginType list field. `FUN_146e1c3f0` iterates this list and writes
entries into `loginSM + 0x218..+0x220`.

**Implication:** Whatever TDF tag maps to PreAuthResponse offset +0x120
in the member info table at `0x144874a90` IS the login types field.
If our server doesn't emit this tag, the list stays empty.

---

### FACT: BF4's working PreAuth response has these top-level tags
Decoded from `BF4BlazeEmulator/Components_Client/Util.py`:
- `ASRC` = "302123"
- `CIDS` = list of 22 component IDs
- `CONF` = struct containing map (17 config entries)
- `ESRC` = "302123"
- `INST` = "battlefield-4-pc"
- `MINR` = 0
- `NASP` = "cem_ea_id"
- `PILD` = ""
- `PLAT` = "pc"
- `QOSS` = struct with BWPS (bandwidth probe server), LNP, LTPS (map)
- (more after QOSS — decoder hit a bug, but these are the confirmed ones)

**Note:** None of these obvious tags (`ASRC`, `CIDS`, `CONF`, `QOSS`) are
candidates for "login types" — they're infrastructure. Login types must
be one of the remaining tags BF4 sends after QOSS.

BF4 RPC command table (from BF4BlazeEmulator/Components_Server/Authentication.py):
cmd 0x0010=CreateAccount, 0x0028=Login, 0x0032=SilentLogin,
0x003C=ExpressLogin, 0x0046=Logout, 0x0098=OriginLogin,
0x0050=CreatePerson, 0x006E=LoginPersona.

---

### FACT: DLL Patch 3 bypasses the LSX GetAuthCode flow entirely
From `FUN_1470db3c0` (OriginRequestAuthCodeSync) normal flow:
```c
if (!FUN_1470e2840()) { error 0xa0010000; }
else { uVar2 = FUN_1470e3560(); FUN_1470e67f0(uVar2, ...); }
```

Patch 3 rewrites the function body to write a fake auth code directly
to `[R8]` and return 0. This **never calls `FUN_1470e67f0`**, so:
- No LSX `GetAuthCode` is sent
- `FUN_1470e6540(sdk, 1, authCode)` never runs
- Any Origin SDK internal state that gets set as a side-effect of a
  successful auth code retrieval is NEVER set

This was confirmed in Session 2 / Phase 10: Origin IPC server received
0 GetAuthCode requests, even though it handles them correctly.

**HYPOTHESIS:** Some higher-level check (possibly in the online state
machine `FUN_146f30710`) relies on state that `FUN_1470e6540` sets.
Without it, the online state machine decides "user is not authenticated"
and triggers `LoginAdaptor::Logout`.

---

### HYPOTHESIS: Three candidate failure modes
Based on the above, the Logout decision is one of these:

**H1 — Login types array empty.** PreAuth response doesn't contain the
TDF field at offset +0x120, so `FUN_146e1c3f0` leaves `+0x218/+0x220`
empty. `FUN_146e1dae0` returns 0 and `FUN_146e19b30` (fallback) runs.
The fallback eventually triggers Logout.

**H2 — Origin SDK "logged in" state not properly set.** DLL Patch 3
provides a fake auth code but skips the internal state updates. The
online state machine sees "no real Origin session" and logs out.

**H3 — Connection state (+0x1c0 or +0x13b8) stuck in error state.**
The online tick `FUN_146f33340` checks `+0x1c0` against specific values.
If it returns the wrong thing, the online state machine bails.

The Frida flow trace will tell us which one is the actual cause.

---

### TEST: `frida_flow_trace.js` — passive observation

Instrumented functions (no patches, just logging):
- `0x146e1cf10` PreAuth handler — entry args, state at exit
- `0x146e1c3f0` Login types processor — count of entries populated
- `0x146e1dae0` Login check — returns 0 (empty) or 1 (sent)
- `0x146e1eb70` Login RPC sender — **critical: does this ever fire?**
- `0x146e19b30` Login fallback (no types)
- `0x1470db3c0` OriginRequestAuthCodeSync — currently patched, sees cave call
- `0x1470e67f0` Origin LSX RequestAuthCode — should NOT fire under Patch 3
- `0x1470e2840` IsOriginSDKConnected — DAT_144b7c7a0 != 0
- `0x146f199c0` FirstPartyAuthTokenReq — per-frame slot iterator
- `0x147102800` LoginEventDispatcher — from Origin `<Login>` event
- `0x146df0e80` RpcSend — fires `🚨 LOGOUT SENT` with full stack trace
- `0x6dab760`   RpcBuilder — component/command registration
- `0x146e126b0` SM_Transition — every state machine transition
- `0x1470e6ee0` LSX_SendXml — every XML message sent
- `0x146f7c7e0` OnlineTick — per-frame state snapshot (every 60 ticks)

State checkpoints dump:
- OnlineManager: +0x1c0, +0x1f0, +0x13b8, +0x4e98..0x4ed8, +0xb10
- BlazeHub: +0x53f
- loginSM: +0x218/+0x220, +0x18 (job handle)
- OriginSdkObject: +0x3a0 (userId), +0x35c (port)

Run command: `flow_trace_test.ps1` (automated — builds DLL, starts
servers, launches game, attaches Frida, drives menus, collects ALL
logs, pushes to git).

---

### EXPECTED OUTPUT FROM TEST

What the trace should show us (in order):
1. `HOOKED` messages — every function successfully hooked
2. Initial CHECKPOINT at 2s / 5s / 10s
3. `PreAuthHandler` entry/exit with the response data
4. `LoginTypesProcessor` called with count — **count=0 means H1**
5. `LoginCheck` returns 0 or 1
6. Either:
   - `LoginSender` fires (🎯) → we were close, just a bug somewhere else
   - `LoginFallback_NoTypes` fires (⚠️) → H1 confirmed
7. Some sequence of `SM_Transition` events
8. `🚨 LOGOUT SENT` with full stack trace — this is the smoking gun

The stack trace tells us the exact function that chose Logout.

---

### TODO after first trace run
- Read `frida_trace_results.log` carefully
- Identify which of H1/H2/H3 is active
- Update this log with findings under a new "Session" entry
- Pick the fix path and implement


---

## Session: April 17, 2026 16:06 — First Flow Trace Run

### RESULT: Verdict classifier was buggy (said LOGIN_SENT), actual outcome = LOGOUT_WIRE

The wire-level truth from the Blaze server (this is ground truth):

```
msgId=2..7   FetchClientConfig x 6 (all 6 OSDK_* sections served)
msgId=17     Ping (low-level, type=4) → pong
msgId=18     Ping (low-level, type=4) → pong
msgId=19     Logout (comp=0x0001 cmd=0x0046 len=0)   ← the wall
msgId=20     Ping
<disconnect>
```

Also:
- Game's second session (after reconnect) repeats the same sequence
  starting at msgId=14 (so the client's msgId counter is shared).

### FACT: IsOriginSDKConnected is hit every ~15ms
The trace was completely dominated by this noise (900 of 1221 lines).
**FIX applied:** only log on value change. Rebuilt script.

### FACT: Real Origin SDK object IS created by the game
`DAT_144b7c7a0 = 0x27a48f10` — this is a game-allocated heap object.
Our DLL's fake SDK object at `DAT_144b86bf8 = 0x1D0000` (pinned in DllMain)
is a DIFFERENT global pointer. Two separate things.

**IMPORTANT:** The game HAS a real Origin SDK object at +0x27a48f10. Our
DLL isn't replacing it. `IsOriginSDKConnected` returns true because the
real object exists.

### FACT: Server pushes `<Login IsLoggedIn="true"/>` but game still logs out
Origin IPC flow completes perfectly:
```
Challenge/Response/Accepted
GetConfig → Config="false"
GetProfile → PersonaId=33068179, UserId=33068179
GetSetting IS_IGO_ENABLED → "false"
GetGameInfo FREETRIAL → "false"
GetSetting ENVIRONMENT → "production"
GetSetting IS_IGO_AVAILABLE → "false"
IsProgressiveInstallationAvailable → Available="false"
[Push] <Login IsLoggedIn="true"/>
GetProfile (2nd call) → same data
GetSetting LANGUAGE → "en_US"
SetDownloaderUtilization → ErrorSuccess
GetSetting ENVIRONMENT → "production"
```

Game accepts ALL of these, yet still sends Logout to Blaze.

### FACT: DLL Patch 3 cave executed, auth code provided
DLL log shows: `AUTH: >>> CAVE EXECUTED! Auth code provided!`
`req[+0xd8]=0x99C9930 req[+0xe8]=1`

So the authentication state in memory says "auth code ready" — but the
game still chose Logout.

### HYPOTHESIS UPGRADED: H2 is confirmed-plausible
The fake auth code is available in memory, BUT the Origin SDK's internal
"logged in" state never got the validation side-effects from a real
GetAuthCode call. The online state machine sees the inconsistency
("we have an auth code but we never actually authenticated with Origin")
and logs out.

### ISSUE: Frida hooks never visible in trace output
The trace's "FRIDA FLOW TRACE (full)" section in the report contained
literally just one line:
```
> 1  (DAT_144b7c7a0 = 0x27a48f10)
```
which is the end of a single `IsOriginSDKConnected` log line.

This means ALL other hook output was eaten by the 60KB tail window.
By the time the script tailed the output, `IsOriginSDKConnected` had
fired ~10000 times and pushed all the important events out.

**FIXED:** (a) rate-limit IsOriginSDKConnected to log only on change,
(b) save the FULL frida output to `frida_trace_full.log`,
(c) include BOTH first-30KB and last-60KB in the report.

### TODO NEXT: Re-run flow_trace_test.ps1 with the fixed script
Expected: we'll finally see the PreAuthHandler / LoginTypesProcessor /
LoginCheck / LoginSender / LOGOUT SENT events with their stack traces.


---

## Session: April 17, 2026 16:14 — BREAKTHROUGH: Root Cause Found

### RESULT: H1 CONFIRMED — Login types array is empty

From `frida_trace_full.log`:

```
[22632] PreAuthHandler(this=0x3eac7ff0 resp=0x3edd5ef0 err=0)
[22632] LoginTypesProcessor(loginSM=0x3eac9da0 resp+0x120=0x3edd6010)
[22632]   resp TDF bytes (first 64): 109d88430100000000000080000000000a...
[22632] LoginCheck(loginSM=0x3eac9da0 count=0)               ← EMPTY!
[22632] LoginCheck returned 0                                 ← FAIL
[22632] ⚠️ LoginFallback_NoTypes called (login types array empty!)
[22634] LoginTypesProcessor done. loginSM+0x218=0x0 +0x220=0x0 count=0
```

**The login types array is empty.** `LoginSender` (`FUN_146e1eb70`) NEVER
fires. Instead `FUN_146e19b30` (fallback for no login types) is called,
and 30 seconds later Logout is sent.

### FACT: The TDF list at PreAuthResponse+0x120 has vtable PTR_FUN_143889d10
First 8 bytes of `resp+0x120` = `0x143889d10` — a VALID game RDATA
pointer. So the TDF list object IS constructed, it's just empty.

The TDF list size indicator at `resp+0x120+0x10 = 0x0a` (10 bytes? entry
count?) and `resp+0x120+0x18 = 0x4388889a0` (some pointer).

**What's missing:** our PreAuth response doesn't write actual TDF list
entries for the login types field. The list object is default-constructed
(empty) when PreAuth response is decoded.

### FACT: Stack trace at Logout reveals the caller
```
0x146e10b43   (inside FIFA17.exe — 1st caller)
0x146e15fa5   (2nd in chain)
0x146e155b4
0x146e126a5   (FUN_146e126b0 vtable[0x10] call dispatch)  ← state machine transition!
0x14717ead8
0x1471b6960
0x1471b7edf
0x1471b37b6   (OSDK/LoginManager code)
0x146f7b9ed   (FUN_146f7c7e0 online tick context)
```

**This confirms:** Logout is triggered by the OSDK LoginManager state
machine, which transitioned to a "give up" state because
`LoginFallback_NoTypes` ran (no login types available → no way to auth).

### FACT: OnlineManager state during Logout
```
OM +0x1c0 = 0xFFFFFFFF  ← never initialized to a real state!
OM +0x1f0 = 0xFFFFFFFF  ← same
OM +0x13b8 = 0          ← idle
BH +0x53f = 1            ← DLL's forced flag (good)
auth slot 0 obj = 0x1438f5d50  ← a GAME-INTERNAL address, not our injected one
  +0xe8 (ready flag) = 96  ← odd value (ASCII 0x60?), not 1
```

Note: `auth slot 0 obj = 0x1438f5d50` is in game RDATA — this is a
pointer to a STRING or SENTINEL, not a real allocated auth request.
The `+0xe8=96` is just garbage from reading into adjacent memory.

### FACT: OriginRequestAuthCodeSync DID fire
```
[3651] FirstPartyAuthTokenReq(base=0x3ec48d08)
[3651]   slot1=0x5d3e0000 slot2=0x0
[3651] OriginRequestAuthCodeSync(userId=0x0 clientId=0x5d3e0018 scope=0x3939fc60 outCode=0x3939fc58)
[3651] OriginRequestAuthCodeSync returned
```

`userId=0x0` !! The DLL Patch 3 cave runs, but it receives `userId=0`
from the caller. That means `FUN_1470da6d0` returned 0 (the SDK's user
id at `+0x3a0` is 0, not our fake 33068179).

Also `Origin_RequestAuthCode_LSX` (`FUN_1470e67f0`) NEVER fires — Patch 3
short-circuits it as expected.

### FACT: Member info table is at 0x144867628 (NOT 0x144874a90)
Ghidra had stale offset. Live dump shows base is `0x144867628`, with
14 entries of what appear to be 40 bytes each. The meaningful entries
(with tag hashes and valid pointers) are indices [9]-[13]:

```
[9]  u32[0]=0x44c21c80  — vtable pointer
[10] u32[0]=0x44c03590  u32[1]=0x1  u32[2]=0x44c03240
[11] u32[0]=0x44bd7730  u32[1]=0x1  u32[2]=0x44b89180
[12] u32[0]=0x44886200  u32[1]=0x1  u32[2]=0x44c02820
[13] u32[0]=0x44c0f900  u32[1]=0x1  u32[2]=0x448a4b70
```

The layout doesn't look like simple {tag, offset, type} — it has what
appear to be pointers. This is likely a structure with `TdfMemberInfo*`
entries that each have their own layout. Need to dump these individual
entries to decode tags.

### THE FIX — Add the LoginType list to our PreAuth response

**The PreAuth response we're sending doesn't include the LoginType TDF
field.** BF4's working PreAuth response probably does — that's why BF4
clients successfully send Login commands after PreAuth.

Our server (`server-standalone/server.mjs`) currently sends these
PreAuth fields: ANON, ASRC, CIDS, CONF, INST, NASP, PLAT, QOSS, RSRC,
SVER, PTVR. **We need to add a LoginType list field.**

In BlazeSDK, this field is typically called:
- `LGTP` or `LTIP` or similar (list of login types)
- A TdfList of strings or integers representing supported login types
- Values typically: `"nucleus"`, `"dotnet"`, `"origin"`, or numeric codes

### NEXT ACTION: Find the exact tag name for the login types list

Options:
1. Dump the member info table entries in detail to extract tag hashes
2. Look at BF4's encoded PreAuth response bytes around the similar
   field location and decode its tag
3. Search Ghidra for BlazeSDK tag strings like "LGTP", "LTIP", etc.

Then add that field to our server.mjs PreAuth response with valid
login type entries (e.g. one entry specifying "nucleus" auth with a
suitable persona namespace).


---

## Session: April 17, 2026 16:47 — TDF Tag Hunt Failed, Switching to Direct Injection

### RESULT: Schema dump did not reveal the TDF tag name
The member info table scan found byte patterns that decode to nonsense
tags (HSR', RHX!, ION., etc.). The TDF tags are stored in a format
different from what I assumed — likely as 32-bit hashes, not raw 3-byte
encoded values.

### DECISION: Stop chasing the tag, inject directly
We know:
1. The login types array at `loginSM+0x218/+0x220` is empty (CONFIRMED)
2. `FUN_146e1dae0` (LoginCheck) returns 0 because the array is empty
3. `FUN_146e1eb70` (LoginSender) fires when the array has entries (v57 proved this)
4. The timing issue in v57 was that injection happened from a background thread

### NEW APPROACH: `frida_inject_login_type.js`
Hook `FUN_146e1dae0` (LoginCheck) at entry. When the array is empty,
inject a fake login type entry BEFORE the function iterates. This runs
on the game's main thread (inside the PreAuth handler call chain), so:
- The Login RPC will be sent on the correct thread
- The Blaze connection will still be alive
- No timing race condition

The entry layout (from `FUN_146e1eb70` analysis):
```
entry+0x00: ptr to non-empty string (flag)
entry+0x18: ptr to config object
  config+0x10: ptr to auth token string
  config+0x28: u16 transport type (0=Login)
```

### TEST: `login_inject_test.ps1`
Runs the game with Frida attached, injects login type on first
LoginCheck call, monitors for LoginSender and Login RPC on wire.

Expected outcomes:
- 🎯 LoginSender fires → Login RPC sent → server responds → PostAuth?
- ⚠️ LoginSender fires but crashes → entry layout is wrong
- ❌ LoginCheck still returns 0 → injection didn't take effect

### RESULT: PENDING — test running now (April 17, 2026 ~17:25)

Test 5 approach: inject in `onEnter` of `FUN_146e1c3f0`, let the game's
own code path call LoginCheck → LoginSender naturally. No manual function
calls from Frida — just data injection.

---

## Complete Session Timeline (April 17, 2026)

### 15:00 — Project onboarding
- Read all documentation: SESSION_LOG.md, FIFA17_SOLUTION.md, FIFA17_ONLINE_FLOW.md,
  SOLUTION_ANALYSIS.md, NEXT_SESSION_PLAN.md, PROJECT_ROADMAP.md
- Read FIFA 17 Server Revival Documentation.txt, FIFA Connection Sequence Workarounds.txt
- Read unknowncheats.txt (BF3/BF4 Blaze emulator community threads)
- Read DLL source (dll-proxy/dinput8_proxy.cpp, 1122 lines, v97)
- Read Frida script (frida_force_login.js, v63)
- Read Blaze server (server-standalone/server.mjs, 1992 lines)
- Read Origin IPC server (server-standalone/origin-ipc-server.mjs, v5)
- Read origin-sdk Rust crate (crypto.rs, random.rs)
- Read BF4 emulator code (BF4BlazeEmulator/)
- Verified Ghidra dump accessible (FIFA17_dumped.bin.c, 6.5M lines, 209MB)

### 15:30 — Initial analysis
- Identified three hypotheses for Logout:
  H1: Login types array empty (PreAuth missing field)
  H2: Origin SDK internal state not set (Patch 3 bypasses LSX)
  H3: Connection state stuck in error
- Proposed 3-phase plan: Observe → Understand → Act

### 15:48 — Phase 1 setup
- Created `frida_flow_trace.js` — passive instrumentation of 15 functions
- Created `flow_trace_test.ps1` — automated test script
- Created `FLOW_TRACE_PLAN.md` — technical spec
- Created `RESEARCH_LOG.md` — this file
- Pushed to git

### 16:02 — First trace run
- RESULT: Verdict classifier bug (said LOGIN_SENT, actually LOGOUT_WIRE)
- IsOriginSDKConnected spam (900/1221 lines) ate the important events
- Fixed: ratelimited IsOriginSDKConnected to log only on change
- Fixed: save full trace + include first 30KB and last 60KB in report
- Fixed: verdict classifier to match exact Frida markers

### 16:14 — Second trace run — BREAKTHROUGH
- **H1 CONFIRMED:** Login types array is empty (count=0)
- LoginCheck returns 0, LoginFallback_NoTypes fires, LoginSender never fires
- Full stack trace at Logout captured (OSDK LoginManager → SM transition)
- OnlineManager state: +0x1c0 = 0xFFFFFFFF, +0x1f0 = 0xFFFFFFFF
- Origin SDK object is real (0x27a48f10), not our DLL's fake

### 16:20 — Phase 2: Understanding
- Decoded BF4 PreAuth response (12 fields, NO login types)
- BF4 uses `-authCode noneed` to bypass — FIFA 17 doesn't support this
- FIFA 17 has 14 PreAuth fields, we send 15 (but none are login types)
- The login types field is at PreAuth response object offset +0x120
- It's a TDF list with vtable 0x143889d10, constructed but empty

### 16:30 — Ghidra deep dive
- Found LoginStateMachineImpl constructor (3 sub-state-machines at indices 1,2,4)
- Confirmed SM[3]=NULL (explains earlier crash on state transition 2,1)
- Found PreAuthResponse has 14 TDF member info entries
- Found string table with field names: authenticationSource, componentIds,
  clientId, entitlementSource, underage
- Could NOT find the TDF tag-to-offset mapping for offset +0x120

### 16:40 — Schema dump attempt 1
- Created `frida_dump_preauth_schema.js` — dumps member info table
- Found string pointers to field names but not tag encodings
- Table layout is complex (array of pointers, not inline structs)

### 16:47 — Schema dump attempt 2
- Created `frida_decode_preauth_tags.js` — scans for TDF tag byte patterns
- Scanned member info table, registration area, and decoder instructions
- Found byte patterns but they decode to nonsense tags (HSR', RHX!, etc.)
- Tags are stored as 32-bit hashes, not raw 3-byte encoded values

### 16:55 — Phase 3: Direct injection
- DECISION: Stop chasing the TDF tag, inject login type entry directly
- Created `frida_inject_login_type.js` — hooks LoginCheck, injects entry
- Created `login_inject_test.ps1` — automated test
- This is the same approach as Frida v57 but with correct timing
  (on game's main thread, inside PreAuth handler call chain)
- Test running now

### 17:00 — Login Inject Test 1: FAILED (two bugs)
- Bug 1: `ctx.r8` TypeError — Frida uses `this.context`, not `ctx` param
- Bug 2: Frida attached AFTER PreAuth already fired (25s delay before attach)
- Fixes: `this.context.r8` with try/catch, attach Frida BEFORE menus

### 17:05 — Login Inject Test 2: Frida can't hook FUN_146e1dae0
- Error: `unable to intercept function at 0x146E1DAE0`
- Frida can't hook LoginCheck directly (possibly due to DLL patches nearby)
- Fix: Hook `FUN_146e1c3f0` (LoginTypesProcessor) instead, inject in onLeave,
  then call LoginCheck manually via NativeFunction

### 17:07 — Login Inject Test 3: CRASH (progress!)
- Injection succeeded: `count=1` in the array
- Called `FUN_146e1dae0` (LoginCheck) manually → game crashed
- Crash was inside LoginCheck, likely re-entrancy issue (LoginCheck was
  already called by the natural code path, calling it again corrupts state)
- Fix: Call `FUN_146e1eb70` (LoginSender) directly instead of LoginCheck

### 17:12 — Login Inject Test 4: CRASH again
- Called `FUN_146e1eb70` (LoginSender) directly from onLeave
- Game crashed immediately — no return value logged
- Added exception handler + full state dump for diagnostics

### 17:15 — Login Inject Test 5: FREEZE (deadlock!)
- LoginSender called, never returned — game froze completely
- Diagnosis: deadlock. We're calling LoginSender from inside the PreAuth
  response handler's call chain. The RPC framework holds a lock from
  processing the PreAuth response. LoginSender tries to acquire the same
  lock to send a new RPC → deadlock.
- Fix: Don't call any functions manually. Just inject the entry into
  `loginSM+0x218/+0x220` in `onEnter` of LoginTypesProcessor, BEFORE
  the function runs. The natural code path will call LoginCheck → LoginSender.
- Key insight: TDF copy writes to `+0x1b8` (different field), NOT `+0x218`.
  So our injection at `+0x218` won't be overwritten.

### 17:25 — Login Inject Test 6: Running now
- Cleanest approach: inject in onEnter, let game's own code do everything
- No manual NativeFunction calls from Frida — just data injection
- If this works, LoginSender fires naturally and Login RPC goes on the wire


---

## Session: April 17, 2026 16:53 — Login Inject Test 1 FAILED (bugs)

### RESULT: Two bugs prevented the test from working

**Bug 1: `ctx.r8` TypeError in RPC send hook (line 123)**
The Frida `Interceptor.attach` callback uses `this.context` to access
registers, not a `ctx` parameter. The error `TypeError: cannot read
property 'r8' of undefined` crashed the RPC hook. When one hook errors
in Frida, it can suppress subsequent hook callbacks.

**Bug 2: Frida attached AFTER PreAuth already fired**
The test script waited 25 seconds (menu navigation + init), THEN attached
Frida. But PreAuth fires during those 25 seconds. By the time Frida
hooks were installed, PreAuth was done and the game was already in the
Logout timeout path.

The `flow_trace_test.ps1` worked because it attached Frida BEFORE menus.

### FIXES APPLIED
1. Changed `ctx.r8` to `this.context.r8` with try/catch
2. Moved Frida attachment to BEFORE menu navigation (same pattern as
   `flow_trace_test.ps1`)
3. Extended wait times: 40s for connection flow + 30s for Login/PostAuth

### RETEST: Running now


---

## Session: April 17, 2026 17:07 — Login Inject Test 2: CRASH (progress!)

### RESULT: Injection worked, LoginCheck call crashed the game

Frida output:
```
[22703] PreAuthHandler(err=0)
[22703] LoginTypesProcessor(loginSM=0x3eb39da0)
[22705] LoginTypesProcessor: array STILL empty after processing — INJECTING
[22705] Injected: entry=0x10b05d000 config=0x10b05d020
[22705] Array: start=0x10b05d000 end=0x10b05d020 count=1
[22705] Calling FUN_146e1dae0 (LoginCheck) manually...
Process terminated
```

Blaze server: `S1 error: read ECONNRESET` — game crashed during LoginCheck.

### ANALYSIS
The injection succeeded (count=1). The crash happened when we called
`FUN_146e1dae0` manually from `onLeave` of `FUN_146e1c3f0`. Two possible causes:

1. **Re-entrancy:** `FUN_146e1c3f0` already called `FUN_146e1dae0` internally
   (which returned 0). Calling it again from the same stack frame may cause
   issues (double-initialization, corrupted state).

2. **Entry layout wrong:** `FUN_146e1eb70` reads `param_2[2]` (offset +0x10)
   as a u32 and shifts right by 1 for a length parameter. We left +0x10 as 0.

### FIXES APPLIED
1. Set `entry+0x10 = 2` (so `2 >> 1 = 1`, safe length value)
2. Call `FUN_146e1eb70` (LoginSender) DIRECTLY instead of going through
   `FUN_146e1dae0` (LoginCheck) — avoids re-entrancy
3. Pass exact parameters: `loginSenderFn(loginSM, entry, config, 1)`


---

## Session: April 17, 2026 17:12 — Login Inject Test 3: CRASH again

### RESULT: Same crash — LoginSender call never returns

```
[22715] Calling FUN_146e1eb70 (LoginSender) directly...
Process terminated
```

The crash is inside `FUN_146e1eb70`. We never see the return value.
The entry layout fix (+0x10 = 2) didn't help.

### ANALYSIS: What FUN_146e1eb70 does (from Ghidra)

```c
// Line 1: Cache setup
if (*(longlong *)(param_1 + 0x290) == 0) {
    lVar4 = *(longlong *)(*(longlong *)(param_1 + 8) + 0x788);
    *(longlong *)(param_1 + 0x290) = lVar4;
    if (lVar4 != 0) FUN_146dfd050(lVar4, param_1);  // register callback
}

// Line 2: Guard checks
if ((param_3 != 0) &&
    (((param_4 != 1 || (*(char *)*param_2 != '\0')) &&
      (*(longlong *)(param_1 + 0x18) != 0)))) {

    // Line 3: Pre-login setup
    FUN_146e1e680(param_1, param_4, *param_2);

    // Line 4: Read auth token
    pcVar1 = *(char **)(param_3 + 0x10);
    if ((pcVar1 != NULL) && (*pcVar1 != '\0')) {

        // Line 5: Setup transport
        FUN_1478aa000(*(param_1 + 0x18), 0x73707274, *(u16*)(param_3 + 0x28), 0);

        // Line 6: Send the actual Login RPC!
        iVar2 = FUN_1478aa320(*(param_1 + 0x18), pcVar1,
                    *(u16*)(*(param_1 + 8) + 0x53c), 0,
                    *(u16*)(param_1 + 0x1c8), 0, param_4);
```

Possible crash points:
1. `*(longlong *)(param_1 + 8) + 0x788` — dereferencing parent+0x788
2. `FUN_146e1e680(param_1, param_4, *param_2)` — pre-login setup
3. `FUN_1478aa000(*(param_1 + 0x18), ...)` — transport setup
4. `FUN_1478aa320(...)` — the actual RPC send

### FIX: Add exception handler + full state dump before the call
Added `Process.setExceptionHandler` to catch the exact crash address,
plus dumps of all loginSM fields that LoginSender reads.


---

## Session: April 17, 2026 17:15 — Login Inject Test 4: FREEZE (deadlock)

### RESULT: Game froze — LoginSender blocked, never returned

Frida output:
```
[22584] Calling FUN_146e1eb70 (LoginSender) directly...
[no more output — game frozen]
```

No crash, no exception — the function simply never returned.
The game became completely unresponsive.

### ANALYSIS: Deadlock

`FUN_146e1eb70` calls `FUN_1478aa320` (RPC send) which likely tries to
acquire a mutex or enqueue work on the RPC framework. But we're calling
this from inside the `onLeave` of `FUN_146e1c3f0`, which is itself called
from the PreAuth response handler. The RPC framework is still processing
the PreAuth response — it holds a lock that `FUN_1478aa320` needs.

**Classic deadlock:** Thread A holds Lock X (PreAuth processing) and tries
to acquire Lock Y (RPC send queue). But Lock Y requires Lock X to be
released first (or the RPC framework is single-threaded and can't process
a new send while still in a response handler).

### FIX: Inject in onEnter, let natural code path handle it

Instead of calling LoginSender ourselves, inject the entry into
`loginSM+0x218/+0x220` at the START of `FUN_146e1c3f0` (onEnter).
The function's natural code will then:
1. Do the TDF copy (writes to +0x1b8, doesn't touch +0x218)
2. Call `FUN_146e1dae0` (LoginCheck) which reads +0x218/+0x220
3. LoginCheck sees count=1, calls `FUN_146e1eb70` (LoginSender)
4. LoginSender runs in the natural code path — no deadlock

The key insight: the TDF copy writes to `loginSM+0x1b8` (raw TDF data),
NOT to `loginSM+0x218/+0x220` (processed login entries). These are
different fields. So writing to +0x218/+0x220 in onEnter won't be
overwritten by the TDF copy.


---

## Session: April 17, 2026 17:25 — Login Inject Test 6: CRASH (wrong data in +0x218)

### RESULT: Game crashed when natural code iterated our fake entry

```
[22736] INJECTING login type entry into loginSM+0x218/+0x220
[22736] Injected: entry=0x107b93e40 config=0x107b93e60
Process terminated
```

### ROOT CAUSE IDENTIFIED

`FUN_146e1c3f0` reads `+0x218/+0x220` IMMEDIATELY after the TDF copy
and iterates the entries in a loop:

```c
for (; lVar7 != lVar1; lVar7 = lVar7 + 0x20) {
    uVar3 = FUN_146138430(0x83, 0xfffffffe, 1);
    puVar4 = (undefined4 *)FUN_146dd6ec0(param_1 + 0x38, lVar7);
    *puVar4 = uVar3;
}
```

`FUN_146dd6ec0(param_1 + 0x38, lVar7)` treats `lVar7` as a pointer to
a **real BlazeSDK TDF LoginTypeInfo object with a vtable**. Our fake
entry is just raw pointers — no vtable. The function dereferences the
vtable and crashes.

**The +0x218/+0x220 array contains TDF objects, not simple structs.**
We cannot inject into this array without constructing proper TDF objects.

### NEW APPROACH: Interceptor.replace on FUN_146e1dae0

Instead of injecting data, replace the LoginCheck function entirely.
Our replacement:
1. Calls the original LoginCheck first (returns 0 = no types)
2. Then calls FUN_146e1eb70 (LoginSender) directly with our fake entry
3. Returns 1 to indicate "login sent"

This avoids touching +0x218/+0x220 entirely. LoginSender doesn't iterate
the TDF array — it just reads simple fields from the entry we provide.

If `Interceptor.replace` fails (same issue as `attach`), fallback to
hooking LoginTypesProcessor onLeave with `setTimeout(0)` to call
LoginSender outside the PreAuth handler stack (avoids deadlock).


---

## Session: April 17, 2026 17:30 — Login Inject Test 7: No crash, but LoginCheck never called

### RESULT: Interceptor.replace succeeded, but replacement never invoked

```
[22623] PreAuthHandler(err=0)
[22623] LoginTypesProcessor(loginSM=0x3eb39da0)
[22625] LoginTypesProcessor done
[22625] PreAuthHandler done
[22707] RPC: FetchClientConfig x6
[52872] Logout RPC sent
```

`Interceptor.replace` on `FUN_146e1dae0` succeeded (logged at T+0).
But our replacement function was NEVER called. No "LoginCheck:" output
appears between LoginTypesProcessor and PreAuthHandler done.

### ANALYSIS

`FUN_146e1c3f0` has this gate:
```c
if (*(char *)(*(longlong *)(param_1 + 8) + 0x53f) != '\0') {
    // ... iteration + LoginCheck ...
}
```

If `loginSM+0x08` (parent pointer) `+0x53f` is 0, the entire block
including LoginCheck is SKIPPED. The DLL forces `BlazeHub+0x53f = 1`,
but `loginSM+0x08` might point to a DIFFERENT object than the BlazeHub
the DLL is patching.

### FIX: Check and force `loginSM+0x08+0x53f` in LoginTypesProcessor onEnter

Added diagnostic to read `*(loginSM+8)+0x53f` and force it to 1 if 0.
This ensures the LoginCheck gate passes regardless of which object
loginSM's parent points to.


---

## Session: April 17, 2026 17:35 — Login Inject Test 8: LoginSender fired but from WRONG source

### RESULT: LoginSender fired (returned 0x99A5A01) but Login RPC never on wire

Key findings:
1. `parent+0x53f = 1` — the flag IS set, LoginCheck gate passes
2. `Interceptor.replace` succeeded
3. BUT our replacement errored: `TypeError: not a function` at line 60
   — `origLoginCheck(param_1)` failed because `Interceptor.replace`
   invalidates the original NativeFunction reference
4. The LoginSender that actually fired was from the **DLL's background
   thread** (`LOGIN-INJECT` at T+27s), NOT from our Frida replacement
5. DLL's background thread call queues the RPC on the wrong thread →
   Login RPC never dispatched on the wire

### FIX: Don't call origLoginCheck at all

Our replacement should:
1. Skip calling the original (it just returns 0 for empty array)
2. Call LoginSender directly with our fake entry
3. Return 1

This runs on the game's main thread (inside the PreAuth handler call
chain via `FUN_146e1c3f0` → our replaced `FUN_146e1dae0`). No deadlock
because `FUN_146e1dae0` is the LAST thing `FUN_146e1c3f0` calls before
returning — the RPC framework lock should be released by then.

Wait — will this deadlock like test 5? In test 5, we called LoginSender
from `onLeave` of `FUN_146e1c3f0`. Now we're calling it from INSIDE
`FUN_146e1dae0` which is called BY `FUN_146e1c3f0`. Same stack depth.

BUT — in test 5, we called LoginSender from Frida's `onLeave` callback
which runs in Frida's interceptor context. Now we're calling it from a
`NativeCallback` that completely REPLACES the function — the game thinks
it's running `FUN_146e1dae0` natively. This might make a difference for
lock acquisition.

### RISK: Possible deadlock again

If it deadlocks, the fallback is to use `setTimeout(0)` from the
replacement to schedule the LoginSender call on the next Frida tick,
which runs outside the PreAuth handler stack.


---

## Session: April 17, 2026 17:40 — Login Inject Test 9: CRASH after LoginSender returns

### RESULT: LoginSender fired FROM OUR CODE, returned job handle, then crash

```
[30324] LoginCheck REPLACED: calling LoginSender directly
[30324]   jobHandle = 0x2dd41a70
[30328] 🎯 LoginSender returned 160790017 (0x9953A01)
Process terminated
```

### ROOT CAUSE: param_1+0x258 (processed entries array) not initialized

`FUN_146e1eb70` (LoginSender) calls `FUN_146e19090(param_1 + 600, ...)` 
which accesses `param_1 + 0x258`. This array is normally resized and
populated by the iteration loop in `FUN_146e1c3f0` BEFORE LoginCheck
is called. Since our replacement skips the iteration, the array is
uninitialized → crash when LoginSender tries to write to it.

### FIX: Use setTimeout(100) to call LoginSender AFTER PreAuth handler returns

Instead of calling LoginSender inside the replacement, schedule it
via `setTimeout(100)`. This:
1. Returns 1 from our replacement (prevents fallback path)
2. Lets `FUN_146e1c3f0` and the PreAuth handler fully complete
3. 100ms later, calls LoginSender from Frida's event loop
4. At that point, all locks are released and no stack conflicts

Risk: setTimeout runs on Frida's thread, not the game's main thread.
But since we're just calling a NativeFunction, it should execute on
whatever thread Frida's JS runs on. The RPC framework might need to
be called from the game's main thread.

If this deadlocks/crashes, the final fallback is to NOT call LoginSender
at all — instead, just return 1 from LoginCheck and let the game's
own retry logic eventually call LoginCheck again on the next connection
attempt, at which point the DLL's LOGIN-INJECT will have populated
the array from the background thread.


---

## Session: April 17, 2026 17:45 — Login Inject Test 10: FREEZE (setTimeout deadlock)

### RESULT: setTimeout fired, LoginSender returned 0x5180200, then freeze

Same deadlock as test 5. Calling LoginSender from ANY non-game-thread
context (Frida setTimeout, DLL background thread, Frida onLeave) causes
the RPC framework to deadlock.

### KEY INSIGHT: LoginSender MUST be called from the natural code path

Every attempt to call LoginSender from outside the natural flow fails:
- From onLeave of LoginTypesProcessor → deadlock (test 5)
- From DLL background thread → RPC queued but never dispatched (test 8)
- From setTimeout → deadlock (test 10)
- From inside replaced LoginCheck → crash because +0x258 not init (test 9)

The ONLY safe place is inside the natural `FUN_146e1c3f0` code path,
AFTER the array initialization but BEFORE LoginCheck.

### FIX: Initialize +0x258 array, then call LoginSender from replaced LoginCheck

The crash in test 9 was because `param_1+0x258` wasn't initialized.
`FUN_146e1c3f0` calls two functions to initialize it:
```c
FUN_146e192f0(param_1 + 600, count);  // resize array at +0x258
FUN_146f8e7e0(param_1 + 0x38, count); // init tracking array
```

If we call these with count=1 inside our replaced LoginCheck BEFORE
calling LoginSender, the arrays will be properly initialized and
LoginSender won't crash. And since we're inside the natural call chain
(FUN_146e1c3f0 → our replaced FUN_146e1dae0), no deadlock.


---

## Session: April 17, 2026 17:50 — Login Inject Test 11: NO CRASH, NO FREEZE!

### RESULT: LoginSender fired, returned job handle 0x9917601, no crash!

```
[32937] LoginCheck REPLACED: initializing arrays + calling LoginSender
[32937]   jobHandle = 0x2a7d1950
[32937]   Arrays initialized. Now calling LoginSender...
[32937] 🎯 LoginSender returned 0x9917601
[32938] EXCEPTION: not a function  ← minor JS error, not a crash
[32939] LoginTypesProcessor done
[32939] PreAuthHandler done
[33021] RPC: FetchClientConfig x6
[63187] ⚠️ Logout RPC sent
```

### ANALYSIS: Login job queued but never dispatched

LoginSender returned a non-zero job handle (0x9917601), meaning the
Login RPC was successfully queued in the job scheduler. But:
- FetchClientConfig RPCs fire normally (T+33021)
- Login RPC never appears on the Blaze server wire
- 30 seconds later, Logout fires

The Login job IS in the scheduler but something prevents it from
dispatching. Possible causes:
1. Job timeout expired before dispatch
2. Job was cancelled by the Logout path
3. Job scheduler has a condition that prevents Login dispatch
4. The job's callback (LAB_146e1d730) needs additional state

### MINOR BUG: `EXCEPTION: not a function`
`result.toInt32()` fails because NativeFunction returns a NativeReturnValue.
Need to use `result.toNumber()` or cast differently. Not the cause of
the Login failure — just a JS type error.

### PROGRESS SUMMARY (Tests 1-11)
- Test 1-2: Hook bugs (fixed)
- Test 3: Frida can't hook FUN_146e1dae0 (switched to replace)
- Test 4-5: Crash/deadlock from wrong call context
- Test 6: Crash from writing to TDF array (+0x218)
- Test 7: LoginCheck never called (+0x53f flag issue, was actually OK)
- Test 8: LoginSender fired from DLL (wrong thread), not our code
- Test 9: LoginSender fired from our code, crash (uninitialized +0x258)
- Test 10: setTimeout deadlock
- **Test 11: LoginSender fired, no crash, job queued — but never dispatched**

We're ONE step away. The Login job is in the scheduler. We need to
figure out why it's not being dispatched, or find a way to force it.


---

## Session: April 17, 2026 18:44 — Tests 12-13: CRASH from diagnostic hooks

### RESULT: Both crashed right after FUN_1478aa320 returned 0x2

The crash pattern is identical in both tests:
```
FUN_1478aa320 returned: 0x2
Process terminated
```

### ROOT CAUSE: Diagnostic hooks corrupted the call stack

Test 11 (same LoginSender code, no extra hooks) → NO CRASH.
Tests 12-13 (added hooks on FUN_146e19720 + FUN_1478aa320) → CRASH.

`Interceptor.attach` on `FUN_1478aa320` inserts a trampoline at the
function entry. This function is called FROM INSIDE LoginSender. The
trampoline modifies the stack/registers in a way that corrupts the
return path after `FUN_1478aa320` returns to LoginSender.

This is a known Frida issue with functions that use non-standard calling
conventions or have very tight register usage.

### FIX: Strip ALL non-essential hooks

Reverted to minimal configuration matching test 11:
- Replace FUN_146e1dae0 (LoginCheck) ← the core fix
- Monitor RPC send (auth commands only)
- Monitor PreAuth handler
- Monitor LoginTypesProcessor (with +0x53f force)
- Monitor state transitions

NO hooks on: FUN_146e19720, FUN_1478aa320, FUN_1478abf10, LAB_146e1d730

### COMPLETE TEST LOG (Tests 1-13)

| Test | Approach | Result | Root Cause |
|------|----------|--------|------------|
| 1 | Hook LoginCheck onEnter | FAIL | ctx.r8 TypeError + late attach |
| 2 | Fix bugs | FAIL | Frida can't intercept FUN_146e1dae0 |
| 3 | Hook LoginTypesProcessor onLeave, call LoginCheck | CRASH | Re-entrancy |
| 4 | Call LoginSender from onLeave | CRASH | entry+0x10 was 0 |
| 5 | Add diagnostics, call LoginSender from onLeave | FREEZE | Deadlock (RPC lock) |
| 6 | Inject into +0x218 in onEnter | CRASH | TDF objects need vtables |
| 7 | Interceptor.replace LoginCheck, call orig | NO CRASH | origLoginCheck invalid, DLL's LoginSender fired instead |
| 8 | Replace LoginCheck, call orig (with +0x53f check) | NO CRASH | Same as 7, DLL fired LoginSender |
| 9 | Replace LoginCheck, call LoginSender directly | CRASH | param_1+0x258 not initialized |
| 10 | Replace LoginCheck, setTimeout LoginSender | FREEZE | Deadlock (wrong thread) |
| **11** | **Replace LoginCheck, init arrays + LoginSender** | **NO CRASH** | **Job queued 0x9917601 but never dispatched** |
| 12 | Same as 11 + hook FUN_146e19720/FUN_1478aa320 | CRASH | Hooks corrupted call stack |
| 13 | Same as 12 minus scheduler hook | CRASH | Same — FUN_1478aa320 hook |
| 14 | Same as 11 (minimal hooks) | PENDING | Should reproduce test 11 |

### KEY FINDING: Login job IS queued but never dispatches

From test 11, the Login job was queued (handle 0x9917601) and the game
continued normally (FetchClientConfig x6, no crash). But the Login RPC
never appeared on the Blaze server wire. 30 seconds later, Logout fired.

The job has a 7000ms timeout (from FUN_1478aa0f0 Ghidra analysis).
The job callback is at LAB_146e1d730. Something prevents it from firing.

### NEXT: Reproduce test 11, then investigate job dispatch


---

## Session: April 17, 2026 19:18 — Tests 14-18 Summary

### Test 14: CRASH at step 1 (resize function)
### Test 15: Syntax error — Frida script didn't load (no-op)
### Test 16: CRASH at step 1 (resize function again)
### Test 17: NO CRASH — LoginSender returned 0xA140201, but Login never on wire
### Test 18: CRASH at step 4 (LoginSender) — same intermittent pattern

### KEY FINDING: The crashes are INTERMITTENT

Same code produces different results:
- Test 11: NO CRASH, LoginSender returned 0x9917601
- Test 14: CRASH at step 1 (resize)
- Test 16: CRASH at step 1 (resize)  
- Test 17: NO CRASH, LoginSender returned 0xA140201
- Test 18: CRASH at step 4 (LoginSender)

The intermittent nature confirms a race condition with the DLL's
background thread. The DLL's LOGIN-INJECT code runs concurrently
and modifies loginSM state.

### KEY FINDING: Login job queued but NEVER dispatches on wire

In both successful runs (tests 11 and 17), LoginSender returned a
non-zero job handle, but the Login RPC never appeared on the Blaze
server. The job has a 7000ms timeout. The Logout fires 30 seconds
later (way past the timeout).

The job callback `LAB_146e1d730` never fires. The job scheduler
`FUN_1478abf10` either doesn't run or skips the Login job.

### NEW APPROACH: Return 1 from LoginCheck WITHOUT calling LoginSender

Instead of trying to send the Login RPC through the job system
(which never dispatches), just return 1 from LoginCheck to prevent
the Logout fallback. This changes the state machine behavior.

The goal is to see what the game does when LoginCheck returns 1
but no Login RPC is actually sent. Does it:
- Wait indefinitely? (better than Logout — we can investigate)
- Try a different auth path?
- Show a different error message?
- Eventually retry?

This is an information-gathering test, not a fix attempt.


---

## Session: April 17, 2026 19:38 — Test 19: Observation + New Strategy

### RESULT (Test 19 observation): LoginCheck returns 1, Logout still fires at 30s

Returning 1 from LoginCheck without calling LoginSender doesn't prevent
Logout. The 30-second timeout in the OSDK LoginManager fires regardless.
The Login job is queued but never dispatches on the wire.

### ROOT CAUSE ANALYSIS: Why Login job never dispatches

The BlazeSDK's Login job system works like this:
1. `FUN_146e19720` creates a job with callback `LAB_146e1d730`
2. `FUN_1478aa320` writes the auth token into the job
3. The job scheduler (`FUN_1478abf10`) should fire the callback
4. The callback sends the actual Login RPC on the wire

The job is created and the token is written, but the callback never fires.
This is likely because **the game expects CreateAccount to complete first**.
The normal flow is: PreAuth → CreateAccount → (state machine advances) → Login.
We've been skipping CreateAccount entirely.

### NEW STRATEGY: Fix CreateAccount instead of bypassing it

Instead of trying to bypass CreateAccount and call LoginSender directly,
let the natural CreateAccount flow happen and fix the broken TDF decoder
by writing the correct response values in the handler's onEnter.

The CreateAccount handler (FUN_146e151d0) reads resp[0x10..0x13]:
- resp[0x10] = UID byte (1 = account exists)
- resp[0x13] = persona creation flag (1 = triggers SM_Transition(1,3))

When resp[0x13] = 1:
1. SM_Transition(1,3) fires → enters OSDK persona creation state
2. OSDK screen loads (NOP'd by our patch)
3. OSDK completion handler (FUN_146e15320) fires → SM_Transition(0,-1)
4. State 0 onEnter → should trigger the Login flow

This follows the game's NATURAL auth flow instead of trying to bypass it.
The key question: does the game actually send CreateAccount in our setup?
Previous tests show it doesn't — it goes PreAuth → FetchClientConfig → Logout.
CreateAccount is only sent when the login types array has entries.

BUT — if we DON'T replace LoginCheck, the natural flow will call
FUN_146e19b30 (fallback) which might trigger CreateAccount.


---

### COMPLETE TEST LOG (Tests 1-19)

| # | Approach | Result | Key Finding |
|---|----------|--------|-------------|
| 1 | Hook LoginCheck onEnter | FAIL | ctx.r8 TypeError + late Frida attach |
| 2 | Fix bugs, hook LoginCheck | FAIL | Frida can't intercept FUN_146e1dae0 |
| 3 | Hook LoginTypesProcessor onLeave, call LoginCheck | CRASH | Re-entrancy (LoginCheck called twice) |
| 4 | Call LoginSender from onLeave | CRASH | entry+0x10 was 0 |
| 5 | Add diagnostics, call LoginSender from onLeave | FREEZE | Deadlock (RPC lock held by PreAuth handler) |
| 6 | Inject into +0x218 in onEnter | CRASH | TDF objects need vtables |
| 7 | Interceptor.replace LoginCheck, call orig | OK | origLoginCheck invalid after replace; DLL's LoginSender fired instead |
| 8 | Same + force +0x53f flag | OK | Same — DLL fired LoginSender, not our code |
| 9 | Replace LoginCheck, init arrays + call LoginSender | CRASH | param_1+0x258 not initialized (intermittent) |
| 10 | Replace LoginCheck, setTimeout LoginSender | FREEZE | Deadlock (Frida thread) |
| 11 | Replace LoginCheck, init arrays + LoginSender | **OK** | **Job queued 0x9917601 but never dispatched on wire** |
| 12 | Same + hook FUN_146e19720/FUN_1478aa320 | CRASH | Diagnostic hooks corrupted call stack |
| 13 | Same minus scheduler hook | CRASH | FUN_1478aa320 hook still corrupts |
| 14 | Minimal (same as 11) | CRASH | Intermittent — resize function crash |
| 15 | Same with syntax error | NO-OP | Frida script didn't load |
| 16 | Same (v14 rewrite) | CRASH | Intermittent — resize crash again |
| 17 | Skip array init, just call LoginSender | **OK** | **Job queued 0xA140201, never dispatched** |
| 18 | Same | CRASH | Intermittent LoginSender crash |
| 19 | Return 1 from LoginCheck, no LoginSender | OK | Logout still fires at 30s — returning 1 doesn't help |
| 20 | **Fix CreateAccount response** | **PENDING** | New strategy: let natural flow happen |

### Architecture (current test setup)

```
Windows PC:
  ├─ FIFA17.exe + dinput8.dll (DLL proxy with 21 patches)
  ├─ Frida attached (frida_inject_login_type.js)
  ├─ Node.js: server.mjs (Blaze server on 42230 + 10041)
  └─ Node.js: origin-ipc-server.mjs (Origin IPC on 3216)

Connection flow:
  1. DLL loads → fake SDK object, patches applied ✅
  2. Origin IPC: Challenge → ChallengeAccepted → 13 messages ✅
  3. Blaze TLS → Redirector → Main connection ✅
  4. PreAuth → Ping → 6x FetchClientConfig ✅
  5. CreateAccount → [Frida writes resp values] → SM_Transition(1,3) ← TEST 20
  6. OSDK screen (NOP'd) → completion → SM_Transition(0,-1)
  7. Login → server responds → PostAuth → online menus → FUT?
```
