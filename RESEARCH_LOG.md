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
