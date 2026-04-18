# FIFA 17 Private Server — Complete Experiment Log

**Period:** April 11–18, 2026 (8 days)
**Total commits:** 1,089
**Total meaningful experiments:** ~200+ distinct approaches

---

## Day 1 — April 11, 2026 (149 commits)
### Phase: TLS/SSL Certificate Bypass

**Goal:** Get the game to accept our self-signed TLS certificate for the Blaze redirector connection.

**Connection progress:** Step 2 (TLS Handshake) — game connects to `winter15.gosredirector.ea.com:42230` but rejects our cert.

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| v1–v4 | Replace EA CA cert in memory (DER scan, heap scan, OTG string match) | Cert found but replacement didn't prevent SSL alert | Step 2 |
| v5 | IAT hook on `connect()` to replace cert before handshake | Hook installed but cert still rejected | Step 2 |
| v6–v8 | Trampoline hooks on connect/send, cert scan diagnostics | Crashes or no effect | Step 2 |
| v9–v11 | Match EA's 764-byte cert slot with 712-byte custom cert | Cert replaced but SSL still fails | Step 2 |
| v12 | Switch server to SSLv3 + RC4-SHA cipher (ProtoSSL match) | Server crypto mismatch | Step 2 |
| v13–v14 | Patch algorithmIdentifier OIDs to RSA_PKCS_KEY (Aim4kill ProtoSSL bug) | No effect | Step 2 |
| v15–v19 | Find parsed CA cert struct, replace RSA modulus | Modulus location not found reliably | Step 2 |
| v20–v24 | Set `bAllowAnyCert` flag in ProtoSSLRefT struct (DirtySDK source) | Flag location wrong (offset 0xC20 was incorrect) | Step 2 |
| v25–v27 | Search for "Redwood City" string to find CA cert node | Found cert nodes but couldn't locate modulus | Step 2 |
| Frida v1–v13 | Hook closesocket/send for stack traces, find cert verify code | Identified SSL state machine and error handler addresses | Step 2 |
| Frida v15–v18 | NOP disconnect CALL, change JNE→JMP in SSL error path | Patches applied but timing issue (too late) | Step 2 |
| Frida v20–v24 | Dump State 3 code, set bAllowAnyCert at multiple offsets, block ClientHello | Various failures — patches applied after connection attempt | Step 2 |
| Batch v4–v13 | 26-patch combos: cert_process bypass, JLE NOP, state7 NOP, bAllowAnyCert combos, iState forcing | All failed — Frida patches applied too late (game connects before Frida attaches) | Step 2 |
| dump_exe.js | Dump decrypted FIFA17.exe from memory via Frida | Successfully extracted — enabled offline analysis | — |

**Key finding:** All Frida-based SSL patches fail because the game's first TLS connection happens before Frida can attach. Need DLL-based patching.

---

## Day 2 — April 12, 2026 (150 commits)
### Phase A: DLL-Based SSL Bypass + TLS Handshake

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| v30 | DLL pattern scan for bAllowAnyCert + patch before first connection | Flag location still wrong | Step 2 |
| **GHIDRA** | **Analyzed ProtoSSL struct — real bAllowAnyCert at offset +0x384** | **BREAKTHROUGH** | — |
| v50 | DLL sets bAllowAnyCert at +0x384 | Cert bypass works! | Step 2 ✅ |
| v51 | Filter: only patch structs with valid state at +0x168 | Stable cert bypass | Step 2 ✅ |
| SSLv3 crypto | Rewrite PRF, Finished, MAC for SSLv3 (not TLS 1.0/1.2) | Multiple iterations — SSLv3 PRF differs from TLS | Step 2 |
| v17 | Fix handshake: wait for client Finished before server Finished | **TLS handshake completes!** | Step 3 ✅ |

### Phase B: Blaze Redirector + PreAuth

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| v18–v23 | HTTP-wrapped Blaze, fix header sizes, field offsets | Various header format issues | Step 4 |
| v24–v28 | Debug PreAuth: multi-variant test (5 header/body combos) | Game receives response but disconnects | Step 5 |
| v29 | Test secure=0 vs secure=1 in redirect | secure=0 needed for plaintext main server | Step 4 |
| v30–v31 | DLL v51/v52: patch bAllowAnyCert for BOTH SSL connections | Dual SSL bypass working | Step 3 ✅ |
| **v32** | **PreAuth over TLS works!** | **Game accepts PreAuth response** | **Step 5 ✅** |
| v33–v38 | Improve PreAuth response fields, fix CONF map type, fix TDF varint encoder | Incremental fixes | Step 5 |
| v39 | Verify MAC on close_notify — RC4 stream in sync | close_notify is legitimate (game intentionally disconnects after PreAuth) | Step 5 |
| v40–v44 | Add TDF decoder, fix string decode, simplify response | Game decodes PreAuth but still disconnects | Step 6 |
| **v45** | **CRITICAL FIX: varint continuation bit + nucleusConnect/nucleusProxy URLs** | **Game sends Ping after PreAuth!** | **Step 6 ✅** |
| v46 | Point nucleusConnect/nucleusProxy to local HTTP server | URLs configured | Step 6 |
| v53 | DLL patches Origin SDK availability check to always return true | New patch added | Step 6 |
| v54–v55 | DLL auth bypass: skip Origin auth, set authenticated flag | Auth flag set but game still disconnects | Step 6 |
| v56 | Change INST to 'fifa-2017-pc' | Correct game identifier | Step 6 |
| v58 | Fix CIDS type: List(0x04) not IntList(0x07) | No change in behavior | Step 6 |
| v59 | Send BF4 real captured PreAuth response | Proved issue is NOT response content | Step 6 |
| v61 | Proactive SilentLogin notification after PreAuth | Game ignores unsolicited notifications | Step 6 |

**Key finding:** PreAuth works, game sends Ping + 6x FetchClientConfig, then sends Logout. The game never reaches the Login code path.

---

## Day 3 — April 13, 2026 (158 commits)
### Phase: Authentication Flow + DLL Patches v56–v97

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| v56 | Patch auth bypass flag at [RBX+0x2061] | Flag set but no Login | Step 7 |
| v57 | Replace auth call with fake auth code via code cave | Cave executes but Login still not triggered | Step 7 |
| v58–v61 | Origin IPC: connect() hook, inline hook, trampoline | Denuvo interference, reverted | Step 7 |
| v62–v63 | Patch IsLoggedIntoEA + IsLoggedIntoNetwork to return true | Both patched, still Logout | Step 7 |
| v64–v66 | Aggressive patch timing, auth state diagnostics, cave execution marker | Cave confirmed executing | Step 7 |
| v67 | Patch FUN_1470db3c0 BODY instead of call site | Cleaner auth code injection | Step 7 |
| v68–v72 | Re-inject fake auth request after STP timeout, poll for slot clear, suppress auth fail flag, capture vtable | Auth code delivered (req[+0xe8]=1) but still Logout | Step 7 |
| v73–v75 | Check login gate globals, patch SDK gate FUN_1471a5da0 to return 1 | Gate bypassed | Step 7 |
| v76–v78 | Create fake SDK manager object with vtable stubs | Various crashes | Step 7 |
| v79 | Directly call FUN_146f39b20(0,0) to trigger reconnect | No effect | Step 7 |
| **v80** | **NOP disconnect call in PreAuth completion handler** | **Connection stays open after PreAuth!** | **Step 7 ✅** |
| v81–v89 | Patch login type vtable checks, force BlazeHub+0x53f flag, continuous enforcer | Various combinations — game sends FetchClientConfig but still Logout | Step 8 |
| v90–v93 | Diagnostic dumps: callback chain, login state machine, BlazeHub memory scan | Found NULL pointers in callback chain | Step 8 |
| v94–v95 | Server sends proactive Login+PostAuth+UserSession notifications | Game ignores them | Step 8 |
| v96 | Create fake SDK object in DllMain BEFORE game init | Login state machine created but still Logout | Step 8 |
| **v97** | **Patch FUN_146e1cf10 to bypass RPC framework — always call post_PreAuth** | **Game sends FetchClientConfig x6!** | **Step 8 ✅** |

### Phase: Blaze Header Format Discovery

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Frida v1–v14 | Deep RPC trace, BlazeHub handler hooks, LoginSM dumps | Identified ERR_TIMEOUT (0x40050000) | Step 8 |
| **CRITICAL FIX** | **Blaze header was completely wrong (16-byte vs correct 12-byte)** | **Fixed based on BlazePK-rs/PocketRelay** | Step 8 |
| v98–v99 | NOP cleanup in FUN_146e19a00, replace with RET | Prevent disconnect after PreAuth timeout | Step 8 |

**Key finding:** Game sends PreAuth → Ping → 6x FetchClientConfig → Logout. The Blaze header format was wrong — fixed to 16-byte Fire2 format with correct field positions.

---

## Day 4 — April 14, 2026 (278 commits — most active day)
### Phase A: Header Byte Sweep

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Sweep mode | Auto-cycle through 17 byte12/byte13 combinations | **byte13=0x20 (notify type) produces FetchClientConfig + Auth!** | Step 8 ✅ |
| Lock-in | byte12=0x10(resp), byte13=seq confirmed | Stable response format | Step 8 ✅ |

### Phase B: FetchClientConfig + CreateAccount

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| v100 | Patch OriginCheckOnline to always return online | Still Logout | Step 8 |
| v101 | Patch GetGameVersion + version compare | Version check bypassed | Step 8 |
| OSDK configs | Add OSDK_CLIENT with clientVersion=3175939 | Config accepted | Step 8 ✅ |
| CreateAccount handler | Game sends AUTH=FAKEAUTHCODE with EXTB/EXTI | **CreateAccount received!** | **Step 9** |
| v102 | Patch GetProfileSync + GetSettingSync + SetPresence | LSX errors fixed | Step 9 |
| v106 | Force connState=0 continuously | Prevents premature disconnect | Step 9 |

### Phase C: CreateAccount TDF Decoder Problem

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Frida v15–v20 | Trace CreateAccount handler, hook Winsock, dump response structure | **TDF decoder NEVER populates response object** — offsets +0x10 through +0x13 always zero | Step 9 |
| Various TDF bodies | Full AuthResponse, PCTK+UID, BUID+PNAM, empty body | All produce zeros in response object | Step 9 |
| Patch 16 v1–v8 | DLL bypass for CreateAccount handler: hardcode UID, state transitions (1,3), (1,4), (1,0), immediate RET | State (1,3) triggers OSDK screen, others don't advance | Step 9 |
| TOS/Legal handlers | Handle GetLegalDocsInfo (0xF2), GetTOS (0xF6), GetPrivacyPolicy (0x2F) | Responses served but OSDK screen stuck | Step 10 |

### Phase D: OSDK Screen + State Machine

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Frida v25–v31 | Deep TDF decode trace, state machine advance trace, handler object dumps | Mapped state machine structure | Step 10 |
| Patch 8 v2–v3 | NOP JNZ in PreAuth handler, XOR R8D trampoline | **PreAuth trampoline works — forces success path** | Step 6 ✅ |
| FUN_146e19720 calls | Call login init from cave (sync + bg thread) | Crashes — loginSM not properly initialized | Step 9 |

**Key finding:** CreateAccount TDF decoder is fundamentally broken — never populates response object regardless of what we send. The OSDK account creation screen is a dead end (Nucleus web view that can't load without real Origin).

---

## Day 5 — April 15, 2026 (187 commits)
### Phase A: CreateAccount Bypass Strategies

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Full AuthResponse TDF | Send complete session data in CreateAccount response | Decoder still produces zeros | Step 9 |
| Patch 17 | NOP OSDK Logout function | Prevents post-CreateAccount logout | Step 9 |
| Error 0x0F response | Respond with "account exists" error | Handler takes error path → still Logout | Step 9 |
| QoS server | Add UDP server on port 17502 | Not the root cause | Step 9 |
| Patch 3 error return | Make auth code return ERROR to skip CreateAccount | Game skips CreateAccount! But still Logout | Step 8 |
| Patch 18 | Skip age check (FUN_14717d5d0 → RET) | Age error gone | Step 8 |
| Patch 19 | Force login check return 1 | Returns 1 but skips the iteration loop that sends Login | Step 8 |

### Phase B: OriginLogin Redirect

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Patch 20 | Patch CreateAccount sender to send OriginLogin (cmd=0x98) instead | Wrong call site — game uses different path | Step 9 |
| Frida v46–v49 | Runtime redirect at RPC builder/sender, change cmd + response vtable | Server receives OriginLogin but game still uses CreateAccountResponse decoder | Step 9 |

### Phase C: Direct Memory Write (Frida v50)

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Frida v50 | Write +0x10=1, +0x13=1 directly, NOP OSDK screen loader | **NO LOGOUT for first time! OSDK screen appears** | **Step 10** |
| State (1,3)→(2,1) | Change transition parameters | CRASH — state 2 handler (sm[3]) not initialized | Step 10 |
| Frida v51–v51c | Simulate TOS acceptance with transitions (4,1), (5,1), (3,1), (0,1) | Various — no Login triggered | Step 10 |
| Frida v52 | NUCLEAR — call PostAuth directly after PreAuth | Crash | Step 6 |
| Frida v54 | OSDK completion bypass — state transition (0,-1) from Ghidra | Transition executes but too late | Step 10 |
| Frida v55 | Intercept (1,3) → change to (0,-1) in-place | No OSDK requests but Logout still fires | Step 10 |
| Frida v56 | Block Logout RPC after CreateAccount | Logout blocked → Ping sent instead, but game disconnects TCP | Step 10 |

### Phase D: Login Type Injection (BREAKTHROUGH)

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| **Frida v57** | **Inject fake login type entry into array before FUN_146e1dae0** | **FUN_146e1eb70 (Login RPC sender) CALLED FOR FIRST TIME EVER! Job queued but connection died before dispatch** | **Step 10** |

### Phase E: Origin IPC Discovery

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Frida v58 | Origin IPC intercept — dump XML protocol | Discovered TCP-based LSX protocol on localhost | — |
| v59–v63c | Origin IPC server iterations: port 3216/4216, Challenge format, SendXml user ID fix | Multiple iterations — game freezes on wrong format | Step 7 |
| v64–v65b | Combine Patch 3 + Patch 18 + login type injection + Logout block | Full combo but Login job still doesn't dispatch | Step 10 |

---

## Day 6 — April 16, 2026 (56 commits)
### Phase: Origin IPC Protocol Cracking

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Port 4216 direct | Origin IPC server on game's native port | Game freezes — recv() blocks on wrong format | Step 7 |
| Null-terminated strings | Fix send/parse to use null terminators | Game receives data but doesn't respond | Step 7 |
| Port 3216 + DLL redirect | Redirect via connect() hook | Working redirect | Step 7 |
| Various Challenge formats | `<LSX></LSX>`, null byte, `<LSX><Challenge.../>` | All rejected — game disconnects and retries | Step 7 |
| v62 | Real Origin protocol capture with Wireshark | **Captured complete handshake!** | — |
| **origin-sdk crate** | **Found complete Origin LSX protocol spec (Rust)** | **Challenge must be `<Event><Challenge.../></Event>`** | — |
| **Origin IPC v4** | **Correct LSX protocol with AES-128-ECB crypto** | **Crypto implemented** | Step 7 |

---

## Day 7 — April 17, 2026 (82 commits)
### Phase A: Origin IPC Crypto Breakthrough

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Challenge format fixes | Add sender='EALS', version from Wireshark capture | Format matches real Origin | Step 7 |
| **Session key derivation** | **Brute-forced seed from ChallengeAccepted response — seed 13877** | **ALL 18+ messages decrypted!** | **Step 7 ✅** |
| Origin IPC v5 | All response formats matching Wireshark ground truth | **Full Origin IPC working — game freeze PERMANENTLY FIXED** | **Step 7 ✅** |

### Phase B: Forensic Flow Trace

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Flow trace run 1 | Passive Frida instrumentation of 15 functions | IsOriginSDKConnected spam ate important events | Step 8 |
| **Flow trace run 2** | **Fixed trace — ratelimited noise** | **ROOT CAUSE CONFIRMED: Login types array empty (count=0)** | Step 8 |

### Phase C: Login Type Injection Tests (23 total)

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Test 1 | Hook LoginCheck onEnter | FAIL — ctx.r8 TypeError + late Frida attach | Step 8 |
| Test 2 | Fix bugs, hook LoginCheck | FAIL — Frida can't intercept FUN_146e1dae0 | Step 8 |
| Test 3 | Hook LoginTypesProcessor onLeave, call LoginCheck | CRASH — re-entrancy | Step 8 |
| Test 4 | Call LoginSender from onLeave | CRASH — entry+0x10 was 0 | Step 8 |
| Test 5 | Add diagnostics, call LoginSender from onLeave | FREEZE — deadlock (RPC lock) | Step 8 |
| Test 6 | Inject into +0x218 in onEnter | CRASH — TDF objects need vtables | Step 8 |
| Test 7–8 | Interceptor.replace LoginCheck | OK but DLL's LoginSender fired (wrong thread) | Step 8 |
| Test 9 | Replace LoginCheck, call LoginSender directly | CRASH — param_1+0x258 not initialized | Step 8 |
| Test 10 | setTimeout LoginSender | FREEZE — deadlock (Frida thread) | Step 8 |
| **Test 11** | **Replace LoginCheck, init arrays + LoginSender** | **NO CRASH — job queued 0x9917601 but never dispatched** | **Step 8** |
| Test 12–13 | Same + diagnostic hooks | CRASH — hooks corrupted call stack | Step 8 |
| Test 14–18 | Minimal config, intermittent crashes (race condition with DLL) | Job queued but never dispatches on wire | Step 8 |
| Test 19 | Return 1 from LoginCheck, no LoginSender | Logout still fires at 30s | Step 8 |
| Test 20 | Fix CreateAccount response | CreateAccount never sent in this config | Step 8 |
| Test 21 | Transport type 1 (SilentLogin) | FREEZE | Step 8 |
| Test 22 | Fix PreAuth per Blaze3SDK schema | count=0 (same) | Step 8 |
| Test 23 | Fix CIDS TDF type (0x07→0x04) | count=0 (same) | Step 8 |

---

## Day 8 — April 18, 2026 (30 commits)
### Phase: TDF Schema Investigation

| # | Approach | Result | Reached |
|---|----------|--------|---------|
| Schema dump v1 | Frida script crash — Module.findBaseAddress API change | Fixed for Frida 17.x | — |
| Schema dump v2 | Scan binary .rdata for Taggi-format tag chains | No data found | — |
| Schema dump v3 | Brute force hex dump of member info table | Raw bytes extracted but can't decode tags | — |
| Schema dump v4 | Dump loginSM+0xC8 (root cause investigation) | loginSM+0xC8 is NOT zero — QOSS internal list is the real blocker | — |
| Schema dump v5 | Inject login type entry from template at +0xE0 | Script running — latest experiment | — |

---

## Connection Pipeline Progress Summary

| Step | Description | First Reached | How |
|------|-------------|---------------|-----|
| 1 | DNS Redirect | Day 1 | hosts file: 127.0.0.1 winter15.gosredirector.ea.com |
| 2 | TLS Handshake | Day 2 (v50) | DLL sets bAllowAnyCert at +0x384 (Ghidra analysis) |
| 3 | Redirector | Day 2 (v17) | SSLv3 crypto rewrite + correct handshake flow |
| 4 | Main Blaze Connection | Day 2 (v32) | Plaintext TCP on port 10041 |
| 5 | PreAuth | Day 2 (v32) | TDF-encoded response with correct fields |
| 6 | Ping | Day 2 (v45) | Varint continuation bit fix + nucleusConnect URLs |
| 7 | FetchClientConfig ×6 | Day 4 (sweep) | Correct header format (byte13=0x20) + OSDK configs |
| 8 | Auth Decision | Day 5 (v57) | Login type injection — LoginSender called for first time |
| 9 | CreateAccount | Day 4 | Game sends AUTH=FAKEAUTHCODE — but TDF decoder broken |
| 10 | OSDK Screen | Day 5 (v50) | Frida writes +0x13=1, NOP screen loader |
| 11 | Login RPC | **NEVER REACHED** | Login job queued but never dispatched on wire |
| 12 | PostAuth / Online | **NEVER REACHED** | — |

---

## The Wall

After 1,089 commits and 200+ experiments across 8 days, the project is blocked at **Step 8→11**: the login types array at `loginSM+0x218/+0x220` stays empty because the PreAuth response doesn't contain a FIFA 17-specific TDF field (a `List<UInt64>` at response offset +0x120). Without this field, `FUN_146e1dae0` (LoginCheck) returns 0, `FUN_146e1eb70` (LoginSender) never fires naturally, and the game sends Logout after 30 seconds.

The BlazeSDK (Aim4kill) confirms the standard Blaze3 PreAuthResponse has 14 fields — none of which are login types. FIFA 17 has a custom extension. The exact TDF tag name remains unknown.
