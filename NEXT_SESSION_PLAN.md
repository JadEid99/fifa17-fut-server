# FIFA 17 Private Server — Complete Technical Documentation

## CONNECTION ARCHITECTURE MAP

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GAME STARTUP                                 │
│  DLL loads → DllMain creates fake SDK object at DAT_144b86bf8       │
│  PatchThread starts → applies Patches 1-15 in first ~700ms         │
│  Auth injection: fake request → FUN_1470db3c0 provides auth code    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: DNS REDIRECT                                        ✅     │
│  hosts file: 127.0.0.1 winter15.gosredirector.ea.com                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: TLS HANDSHAKE (Port 42230)                          ✅     │
│  Game sends SSLv3/TLS1.2 ClientHello with RC4-SHA cipher            │
│  Server: manual TLS implementation (Node.js dropped SSLv3)          │
│  DLL Patch 1: cert verification bypass (JNZ→JMP)                    │
│  Server cert signed by our CA, DLL replaces CA modulus in memory    │
│  Full handshake: ServerHello → Certificate → KeyExchange → Finished │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: REDIRECTOR (HTTP-over-TLS)                          ✅     │
│  Game: POST /redirector/getServerInstance                           │
│  Server: returns 127.0.0.1:10041 (main Blaze server)               │
│  REDIRECT_SECURE=0 (plaintext main server)                          │
│  Game closes TLS connection after receiving redirect                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: MAIN BLAZE CONNECTION (Port 10041, plaintext)       ✅     │
│  Raw TCP, 16-byte Blaze Fire2 headers                               │
│  Header: [length:4][ext:2][comp:2][cmd:2][msgId:3][type:1][err:2]   │
│  Message types: 0=Request, 1=Response, 2=Notification, 3=Error      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 5: PreAuth (comp=0x0009, cmd=0x0007)                   ✅     │
│  Game sends: CDAT, CINF (BlazeSDK version, client info), FCCR      │
│  Server responds: ANON, ASRC, CIDS, CONF (config map), INST,       │
│    NASP, PLAT, QOSS (QoS config), RSRC, SVER, PTVR                 │
│  DLL Patch 8: XOR R8D trampoline (force success path)               │
│  DLL Patch 9: FUN_146e19a00 → RET (no disconnect on completion)     │
│  PreAuth handler calls FUN_146e1c3f0 → FUN_146e19720 (Login init)  │
│  TDF decode: 325 of 376 bytes consumed (9 fields read)              │
│  Login job created via FUN_1478aa0f0 (7000ms timeout)               │
│  BUT: login type array at loginSM+0x218 stays empty                 │
│  → Login RPC never fires (FUN_146e1dae0 returns false)              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 6: Ping (comp=0x0009, cmd=0x0002)                      ✅     │
│  Game sends Ping, server echoes with STIM (server time)             │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 7: FetchClientConfig ×6 (comp=0x0009, cmd=0x0001)     ✅     │
│  OSDK_CORE: connIdleTimeout, pingPeriod, etc.                       │
│  OSDK_CLIENT: clientVersion, minimumClientVersion                   │
│  OSDK_NUCLEUS: nucleusConnect, nucleusProxy, nucleusPortal          │
│  OSDK_WEBOFFER: offerUrl                                            │
│  OSDK_ABUSE_REPORTING: enabled=0                                    │
│  OSDK_XMS_ABUSE_REPORTING: enabled=0                                │
│  TDF decode: 4 TDF-READ calls per config (map decoding works)       │
│  DLL patches: version check (Patch 11), version compare (Patch 12)  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 8: CreateAccount (comp=0x0001, cmd=0x000A)             ⚠️     │
│  Game sends: AUTH="FAKEAUTHCODE1234567890", EXTB, EXTI              │
│  Server responds with TDF body (various formats tried)              │
│  TDF decode: 3 TDF-READ calls BUT response object NEVER populated   │
│  Response +0x10 through +0x13 always zero regardless of TDF sent    │
│  CreateAccountResponse has only 2 fields (field count=2)            │
│  Handler (FUN_146e151d0) reads response[0x10-0x13]:                 │
│    +0x10 = UID byte (non-zero = account exists)                     │
│    +0x13 = persona creation flag (non-zero = show OSDK screen)      │
│  If +0x13=0: handler returns without state transition → Logout      │
│  If +0x13=1: calls FUN_146e00f40 + state transition (1,3) → OSDK   │
│                                                                     │
│  CURRENT APPROACH (Frida v50):                                      │
│  - Redirect cmd 0x0A→0x98 at wire level (server sees OriginLogin)   │
│  - Write +0x10=1, +0x13=1 directly via Frida memory write           │
│  - NOP FUN_146e00f40 (OSDK screen loader)                           │
│  - Hook state transition (1,3)→(2,1) to advance to Login            │
│  RESULT: No Logout! State machine advances. OSDK screen appears     │
│  but may be bypassed with correct transition parameters.            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 9: OSDK Account Creation Screen                        ⚠️     │
│  Shows when state transition (1,3) fires with +0x13=1               │
│  Screen is a Nucleus web view (UIWebViewWidget) that loads from     │
│  nucleusConnect URL — but web view never loads (empty page array)   │
│  Game sends: GetLegalDocsInfo (0xF2), GetTOS (0xF6),               │
│              GetPrivacyPolicy (0x2F), then Ping probes              │
│  Screen stuck on loading spinner — TOS responses not processed      │
│  The screen was originally auto-populated by Origin overlay         │
│  Fields show broken localization (*TXT_OSDK_*) — never user-facing  │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 10: Login (comp=0x0001, cmd=0x0028/0x0032/0x0098)     ❌     │
│  NEVER REACHED — blocked by CreateAccount/OSDK screen               │
│  Server has working Login handler (tested via raw socket: 148-byte  │
│  response with full session data, error=0)                          │
│  Login types: 0x28=Login, 0x32=SilentLogin, 0x98=OriginLogin       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 11: PostAuth (comp=0x0009, cmd=0x0008)                 ❌     │
│  NEVER REACHED                                                      │
│  Server has working PostAuth handler (telemetry, ticker config)     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 12: Online Menu / FUT                                  ❌     │
│  NEVER REACHED                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## DLL PATCHES (21 total)

| # | Address | Target | What | Status |
|---|---------|--------|------|--------|
| 1 | Pattern scan | Cert verification | JNZ→JMP bypass | ✅ Active |
| 2 | Pattern scan | Origin SDK check | Always return true | ✅ Active |
| 3 | 0x1470db3c0 | Auth code provider | Returns fake auth code + sets marker | ✅ Active |
| 4 | Pattern scan | Auth flag | [RBX+0x2061]=1 | ✅ Active |
| 5 | Pattern scan | IsLoggedIntoEA | Always return true | ✅ Active |
| 6 | Pattern scan | IsLoggedIntoNetwork | Always return true | ✅ Active |
| 7 | 0x1471a5da0 | SDK gate | Always return 1 | ✅ Active |
| 7b | 0x14389f938+ | Login vtable checks | Return 1 for Login/SilentLogin/ExpressLogin | ✅ Active |
| 8 | 0x146e1cf10 | PreAuth handler | XOR R8D trampoline (force success) + save param_1 | ✅ Active |
| 9 | 0x146e19a00 | PreAuth completion | Immediate RET (no disconnect) | ✅ Active |
| 10 | 0x1470e0390 | OriginCheckOnline | Always return online | ✅ Active |
| 11 | 0x1470da720 | GetGameVersion | Return 0 | ✅ Active |
| 12 | 0x145e280b0 | Version compare | Always match | ✅ Active |
| 13 | Various | GetProfileSync, GetSettingSync, SetPresence | Return 0 (delayed) | ✅ Active |
| 14 | OnlineMgr+0x13b8 | connState | Force 0 continuously | ✅ Active |
| 15 | BlazeHub+0x53f | Connection flag | Force 1 continuously | ✅ Active |
| 16 | 0x146e151d0 | CreateAccount handler | ❌ DISABLED — Frida handles it | ❌ Disabled |
| 17 | 0x1472d62a0 | OSDK Logout | RET (NOP) | ✅ Active |
| 18 | 0x14717d5d0 | Age check | ❌ DISABLED (interferes with auth flow) | ❌ Disabled |
| 19 | 0x146e1dae0 | Login check | ❌ DISABLED (interferes with auth flow) | ❌ Disabled |
| 20 | 0x146e15070 | CreateAccount→OriginLogin | ❌ DISABLED — Frida handles it | ❌ Disabled |
| — | Frida v50 | Multiple strategies | Runtime patching via Frida | ✅ Active |

## EVERY APPROACH TRIED — DETAILED LOG

### Phase 1: TDF Encoding Fix (CreateAccount Response)

**Attempt 1.1: Send PNAM + UID (original)**
- Server sent: `PNAM` (string) + `UID ` (integer) = 22 bytes
- Result: 0 bytes consumed by TDF decoder. Response object all zeros.
- Why: Wrong field names — CreateAccountResponse expects different tags.

**Attempt 1.2: Send full AuthResponse (PocketRelay format)**
- Server sent: AGUP, LDHT, NTOS, PCTK, PRIV, SESS{BUID, FRST, KEY, LLOG, MAIL, PDTL{DSNM, LAST, PID, STAS, XREF, XTYP}, UID}, SPAM, THST, TSUI, TURI = 169 bytes
- Result: TDF decoder reads 3 fields (confirmed by Frida v34). But response object +0x10-0x13 still all zeros (confirmed by Frida v39).
- Why: CreateAccountResponse has only 2 fields. The decoder reads some fields but doesn't map them to the response object's +0x10-0x13 offsets. The TDF decoder for this response type is fundamentally broken — it initializes the object but doesn't populate fields from the TDF body.

**Attempt 1.3: Send BUID + PNAM (minimal 2-field)**
- Result: Same — response object all zeros.
- Why: Same broken decoder regardless of what TDF we send.

**Attempt 1.4: Send error response (0x0F = account exists)**
- Server sent error response with byte13=0x60, error=0x000F
- Result: Handler takes error path (FUN_146e0fd30), still sends Logout.
- Why: Error path also leads to Logout.

### Phase 2: DLL Cave Approaches (CreateAccount Handler Bypass)

**Attempt 2.1: Bypass cave — set state bytes + return**
- Cave: vtable+0xb8 → state object, set 0x8bc=0, 0x8c0=1, 0x8c6=0, return
- Result: OSDK screen eliminated! But game sends Logout.
- Why: The handler's fall-through path (0x8c6=0) doesn't advance the state machine. Caller sends Logout.

**Attempt 2.2: Bypass cave + state transition (1,3)**
- Cave: same as 2.1 + call sm→vtable+0x08(sm, 1, 3)
- Result: OSDK screen appeared (GetLegalDocsInfo, GetTOS, GetPrivacy sent).
- Why: Transition (1,3) IS the OSDK screen trigger (persona creation path).

**Attempt 2.3: Trampoline — let original handler run with fake response**
- Cave: force R8D=0, force RDX=fake response object with +0x10=1, +0x13=0
- Result: CRASH (ECONNRESET). Handler accesses response object's vtable.
- Why: Fake response object doesn't have valid vtable pointers.

**Attempt 2.4: Trampoline — let original handler run (no fake response)**
- Cave: force R8D=0, run original handler code
- Result: CRASH. Handler reads response[0x10]=0, calls vtable+0xb8 which dereferences through zero data.
- Why: TDF decoder never populates response object. Original handler can't run with empty response.

### Phase 3: Login Flow Trigger Attempts

**Attempt 3.1: Call FUN_146e19720 from background thread**
- Called FUN_146e19720(preAuthParam1 + 0x3b6) from DLL bg thread
- Result: CRASH — loginSM+0x08=0 (wrong offset)
- Why: Used byte offset 0x3b6 instead of pointer offset 0x3b6*8=0x1DB0

**Attempt 3.2: Call FUN_146e19720 with correct offset (0x1DB0)**
- Called FUN_146e19720(preAuthParam1 + 0x1DB0) from DLL bg thread
- Result: No crash, no effect. Function is one-shot (checks +0x18 != 0, already called during PreAuth).
- Why: FUN_146e19720 was already called during PreAuth and set +0x18.

**Attempt 3.3: Reset loginSM+0x18 and re-call FUN_146e19720**
- Reset loginSM+0x18=0, then call FUN_146e19720 again
- Result: No crash, no Login RPC sent. Function queues job but job never fires.
- Why: Login type array at +0x218 is empty. FUN_146e1dae0 returns false.

**Attempt 3.4: Inject fake login type entry + call FUN_146e1eb70**
- Allocated fake 0x20-byte entry, set array pointers, called FUN_146e1eb70
- Result: First attempt CRASHED (entry[0] was raw byte, not pointer). Fixed: returned success (0x9917601) but Login RPC queued on wrong thread.
- Why: DLL bg thread can't send RPCs — they're queued but the game's main thread disconnects before processing.

**Attempt 3.5: Proactive SilentLogin notification from server**
- Server sent SilentLogin notification (type=2, byte13=0x40) after PreAuth
- Result: Game ignores unsolicited notifications.
- Why: Game's RPC framework doesn't process notifications it didn't request.

**Attempt 3.6: Respond to Logout as SilentLogin**
- Server intercepted Logout, responded with SilentLogin body (cmd=0x0032)
- Result: Game disconnects client-side regardless of response.
- Why: Logout handler tears down connection regardless of response content.

**Attempt 3.7: Don't respond to Logout**
- Server ignored Logout (no response sent)
- Result: Game disconnects client-side immediately.
- Why: Game doesn't wait for Logout response.

**Attempt 3.8: Raw SilentLogin on separate TCP connection**
- DLL opened new TCP connection to 127.0.0.1:10041, sent SilentLogin packet
- Result: Server responded correctly (148 bytes, error=0). But game doesn't see it.
- Why: Separate connection, not the game's Blaze session.

### Phase 4: Skip CreateAccount Entirely

**Attempt 4.1: Patch 3 returns error (no auth code)**
- FUN_1470db3c0 returns EAX=1 (error) instead of EAX=0 (success)
- Result: Game skips CreateAccount! Shows "age restriction" error.
- Why: Without auth code, game can't send CreateAccount. Age check fails because fake SDK has no DOB.

**Attempt 4.2: Bypass age check (Patch 18)**
- FUN_14717d5d0 → RET (skip age check)
- Result: Age error gone. But game sends Logout after FetchClientConfig.
- Why: Without auth credentials, OSDK has no Login path and disconnects.

**Attempt 4.3: Force login check return 1 (Patch 19)**
- FUN_146e1dae0 → return 1 (always proceed)
- Result: No change — still Logout.
- Why: Patch applied too late (post-load section, after PreAuth). Also, returning 1 skips the login type iteration loop which is what actually sends Login.

**Attempt 4.4: Move Patches 18+19 to early loop**
- Applied before PreAuth runs
- Result: No change — still Logout.
- Why: FUN_146e1dae0 returning 1 skips the loop that calls FUN_146e1eb70 (the actual Login sender). The function needs the loop to execute, not just return true.

### Phase 5: OriginLogin Redirect

**Attempt 5.1: Patch FUN_146e15070 (CreateAccount sender) — wrong call site**
- Changed LEA offset to compute 0x98 instead of 0x0A
- Result: Patch applied but game still sent CreateAccount (cmd=0x0A).
- Why: Game uses a different call site to send CreateAccount. Three call sites exist.

**Attempt 5.2: Frida hook FUN_146dab760 (RPC builder)**
- Changed R8 from 10 to 0x98 in the builder function
- Result: Builder hook fired but send function still sent cmd=10.
- Why: Builder stores command in RPC structure. Send function reads from structure, not registers.

**Attempt 5.3: Frida hook FUN_146df0e80 (RPC send)**
- Changed R9 from 10 to 0x98 at send time
- Result: Server received OriginLogin (cmd=0x98)! Responded with 148-byte Login session.
- BUT: Game still used CreateAccountResponse decoder (vtable=0x14389ac68). Response +0x10=0.
- Why: Response type is determined at RPC registration time, not send time.

**Attempt 5.4: Frida scan RPC structure for vtable swap**
- Scanned RPC structure after build for CreateAccountResponse vtable
- Result: Vtable not found in scanned range.
- Why: Response object is created separately, not stored in the RPC structure.

### Phase 6: Direct Memory Write (Current Approach)

**Attempt 6.1: Frida writes +0x10=1, +0x13=0 in handler onEnter (with DLL cave)**
- Frida wrote values, DLL cave intercepted before handler ran
- Result: Values written but cave returned early (didn't read them).
- Why: DLL Patch 16 cave runs before Frida's hook takes effect on the handler.

**Attempt 6.2: Disable Patch 16, Frida writes +0x10=1, +0x13=0, forces R8=0**
- Original handler runs with Frida-written data
- Result: Handler ran, no crash, but still Logout.
- Why: +0x13=0 path doesn't advance state machine (confirmed definitively).

**Attempt 6.3: Frida writes +0x13=1 + NOP FUN_146e00f40**
- +0x13=1 triggers state transition (1,3). FUN_146e00f40 NOPed.
- Result: **NO LOGOUT for the first time!** OSDK screen appeared but no disconnect.
- Why: State transition (1,3) advances state machine. OSDK screen shows because (1,3) is the persona creation transition.

**Attempt 6.4: Hook state transition (1,3)→(2,1)**
- Change transition parameters to match PreAuth's (2,1)
- Result: CRASHED — state 2 handler (sm[3]) may not be initialized
- Theory was wrong: (2,1) is not the correct transition

**Attempt 6.5: OSDK Completion Bypass — transition (0, -1) [CURRENT TEST]**
- KEY DISCOVERY from Ghidra: FUN_146e15320 (OSDK completion handler) calls
  state transition (0, 0xFFFFFFFF) when account creation finishes
- This is what normally fires when the user completes the OSDK screen
- Strategy: Let (1,3) fire, NOP OSDK screen, then immediately call (0, -1)
  to simulate OSDK completion
- This should advance the state machine back to state 0, which should
  trigger the Login flow
- Frida v54 implements this approach

## KEY GHIDRA FUNCTIONS

| Address | Name | Purpose |
|---------|------|---------|
| 0x146e1cf10 | PreAuth handler | Processes PreAuth response, calls Login init |
| 0x146e151d0 | CreateAccount handler | Reads response[0x10-0x13], sets state |
| 0x146e15070 | CreateAccount sender | Builds and sends CreateAccount RPC |
| 0x146e1c3f0 | Login type processor | Inits loginSM, reads login types from PreAuth |
| 0x146e19720 | Login start | Creates login job (one-shot, checks +0x18) |
| 0x146e1dae0 | Login check | Iterates login type array, calls FUN_146e1eb70 |
| 0x146e1eb70 | Login RPC sender | Sends auth token via FUN_1478aa320 |
| 0x146e1e0f0 | PreAuth sender | Builds and sends PreAuth RPC |
| 0x146e213e0 | PostAuth setup | Sets up session after successful Login |
| 0x146e00f40 | OSDK screen loader | Loads web view page by index |
| 0x146df0e80 | RPC send | Generic Blaze RPC dispatcher |
| 0x146dab760 | RPC builder | Builds RPC structure with component+command |
| 0x146db5d60 | RPC response decoder | Dispatches to vtable+0x30 decoder |
| 0x146db5a60 | RPC response dispatcher | Routes by message type |
| 0x1478aa0f0 | Job creator | Creates async RPC jobs with timeout |
| 0x1478abf10 | Job scheduler | Runs queued jobs |
| 0x14717d5d0 | Age check | Checks DOB, shows underage error |
| 0x1472d62a0 | OSDK Logout | UI-level logout function |
| 0x1470db3c0 | Auth code provider | Gets auth code from Origin/STP |
| 0x146e19840 | PreAuth TDF decoder | vtable+0x30 for PreAuthResponse |
| 0x146e12a60 | CreateAccount TDF decoder | vtable+0x30 for CreateAccountResponse |

## BLAZE PROTOCOL

### Header Format (16 bytes)
```
[0-3]   u32  payload length (big-endian)
[4-5]   u16  extended length (usually 0)
[6-7]   u16  component (big-endian)
[8-9]   u16  command (big-endian)
[10-12] u24  message ID (big-endian, 3 bytes)
[13]    u8   [type:3 bits (top)][flags:5 bits (bottom)]
[14-15] u16  error code (big-endian)
```

### Message Types (byte13 >> 5)
- 0 (0x00): Request
- 1 (0x20): Response
- 2 (0x40): Notification
- 3 (0x60): Error response
- 4 (0x80): Ping/Pong

### Key Components
- 0x0001: Authentication (CreateAccount, Login, SilentLogin, OriginLogin, Logout, etc.)
- 0x0005: Redirector (GetServerInstance)
- 0x0009: Util (PreAuth, PostAuth, Ping, FetchClientConfig)
- 0x7802: UserSessions

### TDF Encoding
- Tag: 3 bytes encoded from 4 ASCII chars
- Types: 0x00=Integer, 0x01=String, 0x02=Blob, 0x03=Struct, 0x04=List, 0x05=Map, 0x06=Union, 0x07=IntList
- VarInt: first byte has 6 data bits, continuation bytes have 7 data bits

## BUILD & TEST
```
git pull
.\frida_test.ps1           # Primary — Frida does runtime patching
.\batch_test_lsx.ps1       # For DLL-only changes
```

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script (v50)
- `batch_test_lsx.ps1` / `frida_test.ps1` — Test scripts
- Ghidra export: `/Users/jadeid/Downloads/ghidra/FIFA17_dumped.bin.c`
