# FIFA 17 Private Server — Master Plan

## Status: Phase 1 COMPLETE, Phase 2 PARTIAL, Phase 3 IN PROGRESS

---

## Phase 1: Forensic Observation ✅ COMPLETE

**Goal:** Build a complete, verified map of the game's decision-making from
PreAuth completion to Logout.

**Deliverable:** We now have a full passive Frida trace (`frida_trace_full.log`)
showing every function call in the auth chain with timestamps and state dumps.

### Key Findings from Phase 1

1. **Root cause confirmed: Login types array is empty.**
   - `FUN_146e1c3f0` (LoginTypesProcessor) runs after PreAuth
   - `loginSM+0x218 = 0x0`, `loginSM+0x220 = 0x0` → count = 0
   - `FUN_146e1dae0` (LoginCheck) returns 0
   - `FUN_146e19b30` (LoginFallback_NoTypes) fires
   - `FUN_146e1eb70` (LoginSender) NEVER fires
   - 30 seconds later, OSDK LoginManager state machine sends Logout

2. **Complete call stack at Logout:**
   ```
   0x146e10b43 → 0x146e15fa5 → 0x146e155b4 → 0x146e126a5 (SM transition)
   → 0x14717ead8 → 0x1471b6960 → 0x1471b7edf → 0x1471b37b6 (OSDK LoginMgr)
   → 0x146f7b9ed (online tick)
   ```

3. **OnlineManager state during Logout:**
   - `+0x1c0 = 0xFFFFFFFF` (never initialized to a real state)
   - `+0x1f0 = 0xFFFFFFFF` (never initialized)
   - `+0x13b8 = 0` (idle)
   - `BlazeHub+0x53f = 1` (DLL forced)

4. **Origin SDK is real (not our fake):**
   - `DAT_144b7c7a0 = 0x27a48f10` — game-allocated heap object
   - `IsOriginSDKConnected` returns 1 consistently
   - Origin IPC completes full 13-message handshake

5. **DLL Patch 3 cave executes but doesn't help:**
   - `req[+0xd8] = auth code pointer`, `req[+0xe8] = 1`
   - Auth code IS delivered, but the login types array is still empty
   - The auth code and login types are independent systems

---

## Phase 2: Understanding — PARTIAL

**Goal:** Know what a working auth flow looks like.

### What We Found

1. **BF4 emulator PreAuth response decoded (12 fields):**
   ASRC, CIDS, CONF, ESRC, INST, MINR, NASP, PILD, PLAT, QOSS, RSRC, SVER
   — **No login types field.** BF4 uses `-authCode noneed` command line
   to bypass the login type check entirely. FIFA 17 doesn't support this.

2. **FIFA 17 PreAuthResponse has 14 TDF fields** (from Ghidra registration):
   `_DAT_144875638 = 0xe` (14 entries in member info table at `PTR_DAT_144874a90`)

3. **Our server sends ~15 fields:**
   ANON, ASRC, CIDS, CNGN, CONF, INST, MINR, NASP, PILD, PLAT, PTAG, QOSS, RSRC, SVER, PTVR
   — None of these populate the login types list at response offset +0x120.

4. **The login types TDF tag name remains unknown.**
   Schema dump attempts (raw byte scan, registration area scan, decoder
   instruction scan) did not reveal the tag. The member info table uses
   32-bit hashes, not raw 3-byte encoded tags.

5. **String table from member info contains field names:**
   `authenticationSource`, `componentIds`, `clientId`, `entitlementSource`, `underage`
   — These are human-readable names, but the TDF tag-to-name mapping
   is done via hash lookup, not direct string matching.

### What We Still Don't Know

- The exact TDF tag name for the login types field
- Whether any other Blaze emulator (Zamboni NHL, PocketRelay) sends this field
- What the real EA server's PreAuth response looked like for FIFA 17

### Why This Doesn't Block Us

We don't need the tag name to fix the problem. We can inject the login
type entry directly into memory at the right moment (Phase 3).

---

## Phase 3: Targeted Solution — IN PROGRESS

**Approach chosen: Direct login type injection via Frida**

Based on Phase 1 findings, we know:
- The login types array at `loginSM+0x218/+0x220` must be non-empty
- `FUN_146e1dae0` (LoginCheck) iterates this array
- `FUN_146e1eb70` (LoginSender) is called for each entry
- Frida v57 proved LoginSender works when the array is populated
- v57 failed because injection was from a background thread (timing race)

**The fix:** Hook `FUN_146e1dae0` at entry. When the array is empty,
inject a fake login type entry BEFORE the function iterates. This runs
on the game's main thread (inside the PreAuth handler call chain).

**Current test:** `login_inject_test.ps1` with `frida_inject_login_type.js`

**Test history (Phase 3):**

| Test | Approach | Result | Root Cause |
|------|----------|--------|------------|
| 1 | Hook LoginCheck, inject entry | FAILED | Two bugs: ctx.r8 TypeError + Frida attached too late |
| 2 | Fix bugs, hook LoginCheck | FAILED | Frida can't intercept FUN_146e1dae0 |
| 3 | Hook LoginTypesProcessor onLeave, call LoginCheck manually | CRASH | Re-entrancy: LoginCheck already called by natural path |
| 4 | Call LoginSender directly from onLeave | CRASH | Same crash, entry+0x10 was 0 |
| 5 | Fix entry+0x10, add diagnostics | FREEZE | Deadlock: LoginSender blocks on RPC lock held by PreAuth handler |
| 6 | Inject in onEnter, let natural code path run | RUNNING | Cleanest approach — no manual calls |

**Why Test 6 should work:**
- We inject the login type entry into `loginSM+0x218/+0x220` in `onEnter`
  of `FUN_146e1c3f0` (LoginTypesProcessor)
- The function's natural code does the TDF copy to `+0x1b8` (different field)
- Then it calls `FUN_146e1dae0` (LoginCheck) which reads `+0x218/+0x220`
- LoginCheck sees count=1, calls `FUN_146e1eb70` (LoginSender)
- LoginSender runs in the natural code flow — no deadlock, no re-entrancy
- Login RPC goes on the wire

**If Login RPC hits the wire:**
The server already has Login/SilentLogin/OriginLogin handlers that return
valid session data (SESS struct with BUID, PDTL, KEY, etc.). PostAuth
handler also exists. We'd be past the wall for the first time.

**If Login works but PostAuth fails:**
We'd need to handle whatever the game sends after Login. But that's a
much simpler problem — it's just adding more RPC handlers to the server.

---

## Architecture Reference

```
Game Startup
  ├─ DLL loads → fake SDK object, 21 patches
  ├─ Origin IPC: Challenge → ChallengeAccepted → 13 messages ✅
  ├─ Blaze TLS → Redirector → Main connection ✅
  ├─ PreAuth → Ping → 6x FetchClientConfig ✅
  ├─ LoginTypesProcessor: array empty → LoginCheck returns 0 ← THE WALL
  ├─ LoginFallback_NoTypes → 30s timeout → Logout
  └─ Disconnect

With login type injection:
  ├─ ... (same as above through FetchClientConfig) ✅
  ├─ LoginTypesProcessor: array empty
  ├─ [FRIDA] Inject fake entry into +0x218/+0x220
  ├─ LoginCheck: count=1 → calls LoginSender
  ├─ LoginSender: sends Login RPC with auth token ← NEW
  ├─ Server responds with session data
  ├─ PostAuth → online menus → FUT? ← GOAL
  └─ ...
```
