# FIFA 17 Private Server — Complete Session Log (April 15-16, 2026)

## Architecture
- Windows PC: Runs FIFA 17 + DLL + servers. Game at D:\Games\FIFA 17\
- Mac (Kiro/AI): Edits code, pushes to git. User pulls and tests.
- Git repo: https://github.com/JadEid99/fifa17-fut-server.git

## Connection Pipeline Status (as of end of session)
| Step | Status | Notes |
|------|--------|-------|
| 1. DNS Redirect | ✅ | hosts file: 127.0.0.1 winter15.gosredirector.ea.com |
| 2. TLS Handshake | ✅ | Port 42230, manual SSLv3 implementation |
| 3. Redirector | ✅ | Returns 127.0.0.1:10041 |
| 4. Main Blaze | ✅ | Plaintext TCP port 10041 |
| 5. PreAuth | ✅ | TDF decode works |
| 6. Ping | ✅ | Echo back |
| 7. FetchClientConfig | ✅ | 6 OSDK configs |
| 8. CreateAccount | ⚠️ | TDF decoder broken — never populates response |
| 9. OSDK Screen | ⚠️ | Can be bypassed but leads to Logout |
| 10. Login | ❌ | NEVER REACHED via normal flow |
| 11. PostAuth | ❌ | NEVER REACHED |
| 12. Online Menu | ❌ | NEVER REACHED |

## THE CORE PROBLEM
After PreAuth + FetchClientConfig, the game sends CreateAccount. The CreateAccount TDF decoder is fundamentally broken — it NEVER populates the response object. The handler reads zeros, doesn't advance the state machine, and the game sends Logout.

The login type array at loginSM+0x218 is EMPTY because the PreAuth response doesn't contain login type entries. Without login types, FUN_146e1dae0 returns 0 and no Login RPC is ever sent.

## APPROACHES TRIED — COMPLETE LOG

### Phase 1: TDF Response Variations (v1-v39)
All failed because the CreateAccount TDF decoder is broken regardless of what we send.

### Phase 2: DLL Cave / State Machine (v40-v53)
- Bypass cave with state bytes → Logout still sent
- State transition (1,3) → OSDK screen appears
- State transition (2,1) → CRASHED (SM[3]=0x0, state 2 doesn't exist)
- Direct PostAuth call → returns OK but no session

### Phase 3: Frida v54-v56 — State Machine Manipulation
**v54: State transition (0,-1) from onLeave**
- Discovery: FUN_146e15320 (OSDK completion) calls transition (0, -1)
- Result: Transition executed but TOO LATE — Logout already sent
- Key finding: SM[3]=0x0 confirms state 2 doesn't exist

**v55: Intercept (1,3) → change to (0,-1) in-place**
- Result: No more OSDK requests! But Logout still fires
- Key finding: Logout comes from handler's caller, not state machine

**v56: Block Logout at wire level**
- Result: Logout blocked → Ping sent instead. But game disconnects TCP internally
- Key finding: Game tears down connection regardless of Logout RPC

### Phase 4: Frida v57 — Login Type Injection (BREAKTHROUGH)
**v57: Inject fake login type entry into array before FUN_146e1dae0**
- Result: FUN_146e1eb70 (Login RPC sender) CALLED FOR FIRST TIME EVER
- FUN_146e1dae0 returned 1 FOR FIRST TIME EVER
- Login job queued (returned 0x99cd801)
- BUT: Login RPC never appeared on wire — job queued but connection died before it fired
- Key finding: Login type injection WORKS but timing is wrong

### Phase 5: Origin IPC Discovery (v58-v62)
**v58: Origin IPC Protocol Capture**
- Discovery: Origin SDK uses LSX XML format over TCP on localhost
- Port stored at originSDK+0x35c (was 4216)
- Game sends 11 XML messages during init:
  1. ChallengeResponse (with crypto hash, game ID, version)
  2. GetConfig (to "EbisuSDK")
  3. GetProfile (×3)
  4. GetSetting (ENVIRONMENT, IS_IGO_ENABLED, LANGUAGE)
  5. GetGameInfo (FREETRIAL)
  6. SetDownloaderUtilization
- SendXml returned 0xa2000003 (user ID mismatch — both NULL)

**v59: Origin IPC Server on port 3216**
- DLL patches SDK port from 4216 to 3216
- Result: "Unable to retrieve account information" — NEW ERROR MESSAGE
- Game sent GetSetting + GetProfile XML
- SendXml called but returned 0xa2000003 (NULL user ID)
- Origin IPC server received 0 connections (port patched too late)

**v59b: Disable Patch 3 + DLL port patch**
- Result: Same "account info" error
- Origin IPC server still 0 connections

**v59c: Fake transport object in DllMain**
- Result: GAME CRASHED — fake object had no vtable

**v60: Winsock connect() IAT hook**
- Result: connect() not found in IAT — game uses function pointers

**v60b-d: Hook via game function pointers (DAT_148e223d8)**
- Result: Exception in DllMain (address not mapped yet)
- PatchThread: Patched at ~500ms but too late for initial connection
- Key finding: Game's function pointers at DAT_148e22400 (send), DAT_148e223f8 (recv), DAT_148e223d8 (connect)

### Phase 6: Origin IPC Server on Port 4216 (Direct)
**Listening on 4216 directly:**
- Result: GAME FREEZES at language selection screen
- Game connects, sends 0 messages, blocks in recv()
- Reason: Game's main thread blocks in recv() waiting for server to send first

**Sending Challenge on connect:**
- Result: GAME FREEZES — Challenge format wrong, parser blocks
- Tried: `<LSX><Challenge key="..." version="3"/></LSX>` (with and without \0)

**Sending null byte on connect:**
- Result: Game receives null, disconnects, retries 5 times, 6th stays open → freeze

**Sending `<LSX></LSX>\0`:**
- Result: Same pattern — disconnect, retry, freeze on 6th

### Phase 7: Connect Hook + Grace Period
**15s grace period:**
- Result: Game launches fine (startup connections fail normally)
- But SDK never retries after grace period — 0 connections to our server
- Port 8000 (game HTTP) was accidentally redirected

**5s grace period, only port 4216:**
- Result: Same — SDK connects at 516ms, skipped, never retries

**No grace period, redirect always:**
- Result: Game freezes (back to the freeze problem)
- BUT: DLL log shows SDK retries every ~15 seconds!
- Origin server receives 6 connections
- Game receives our Challenge XML but never responds

### Phase 8: Protocol Capture with Real Origin
**v62: Raw Winsock capture with Origin running**
- Hooked game's function pointers — only captured UPnP traffic
- Origin SDK uses DIFFERENT socket calls (not game's function pointers)

**v62b: Hook ws2_32.dll directly via enumerateExports**
- Successfully hooked ws2_32!send, recv, connect
- But Origin SDK connect() happens before Frida attaches
- No Origin IPC traffic captured

### Phase 9: -authCode Command Line
- Added `-authCode FAKEAUTHCODE1234567890` to commandline.txt (like BF4's `-authCode noneed`)
- Result: Game freezes (connect hook still redirecting to Origin IPC server)
- The -authCode test was contaminated by the freeze issue

## KEY DISCOVERIES
1. **SM[3]=0x0** — State 2 doesn't exist in the auth state machine
2. **Login type injection WORKS** — FUN_146e1eb70 was called, returned job handle
3. **Origin SDK uses TCP on localhost** — null-terminated XML strings
4. **Game sends ChallengeResponse as first XML** — implies Origin sends Challenge first
5. **Protocol is null-terminated** — send() includes length+1 for null byte
6. **Game function pointers ≠ Origin SDK sockets** — two separate networking stacks
7. **SDK retries every ~15s** — when connect hook redirects, SDK retries
8. **Game receives our Challenge but doesn't respond** — format is wrong
9. **"Unable to retrieve account information"** — new error when Patch 3 disabled + port patched

## CURRENT CHOKEPOINT
The game's Origin SDK connects to localhost:4216 during startup. When we redirect to our server:
- Game connects successfully
- We send `<LSX><Challenge key="..." version="3"/></LSX>\0`
- Game receives it (confirmed by WS2-RECV hook)
- Game does NOT send ChallengeResponse back
- Game disconnects and retries every 15 seconds
- Game freezes because main thread is blocked in Origin SDK init

The Challenge XML format is wrong. The game can parse it (doesn't crash) but doesn't recognize it as a valid Challenge, so it disconnects.

## WHAT WE NEED
1. The exact format of Origin's initial message to the game
2. OR a way to bypass the Origin SDK init entirely while still getting a valid auth code
3. OR a way to make the game send SilentLogin instead of CreateAccount

## FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches (v97)
- `server-standalone/server.mjs` — Node.js Blaze server
- `server-standalone/origin-ipc-server.mjs` — Fake Origin IPC server
- `frida_force_login.js` — Frida script (v62b)
- `commandline.txt` — Command-line args for FIFA 17
- `batch_test_lsx.ps1` — DLL-only test
- `frida_test.ps1` — Frida test
- `origin_format_test.ps1` — Origin format test


## CRITICAL DISCOVERY: origin-sdk Rust Crate (github.com/ploxxxy/origin-sdk)

A complete reverse-engineered implementation of the Origin SDK LSX protocol exists as a Rust crate.
This provides the EXACT protocol specification we've been missing.

### Protocol Details

**Transport:** TCP on localhost, null-terminated strings (read_until 0x00)

**Default port:** 3216 (NOT 4216 — `pub const ORIGIN_SDK_PORT: u16 = 3216;`)
- FIFA 17's SDK uses 4216 (older version), but the protocol is the same

**Message format:** `<LSX>` root element with `Request`, `Response`, or `Event` children

**CRITICAL: The Challenge is sent as an EVENT, not a Request/Response!**
```xml
<LSX><Event><Challenge key="random_hex_string"/></Event></LSX>
```
NOT `<LSX><Challenge .../>` (which is what we were sending)

**Challenge Flow (from source code):**
1. Server sends: `<LSX><Event><Challenge key="random_hex_32chars"/></Event></LSX>\0`
2. Client receives, parses as `Lsx { message: Message::Event(Event { body: EventBody::Challenge }) }`
3. Client encrypts the challenge key using AES-128-ECB with DEFAULT key `[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]`
4. Client hex-encodes the encrypted result
5. First 2 bytes of hex string become seed for session key: `seed = (byte[0] << 8) | byte[1]`
6. Client sends ChallengeResponse:
```xml
<LSX><Request recipient="EALS" id="0"><ChallengeResponse>
  <ContentId>1027460</ContentId>
  <key>original_challenge_key</key>
  <response>hex_encoded_encrypted_key</response>
  <Language/>
  <MultiplayerId>1027460</MultiplayerId>
  <Version>9.12.1.2</Version>
</ChallengeResponse></Request></LSX>
```
7. Server verifies, sends: `<LSX><Response id="0"><ChallengeAccepted><response>...</response></ChallengeAccepted></Response></LSX>\0`
8. All subsequent messages are AES-128-ECB encrypted with the session key, hex-encoded

**Encryption:**
- AES-128-ECB with PKCS#7 padding
- Default key (seed=0): `[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]`
- Session key derived from seed using custom PRNG:
  - `MULTIPLIER = 214013, INCREMENT = 2531011, RAND_MAX = 32767`
  - `seed = seed * MULTIPLIER + INCREMENT; return (seed >> 16) & RAND_MAX`
  - Key generation: `rng = Random(7); new_seed = rng.next() + input_seed; rng.set_seed(new_seed); for each byte: key[i] = rng.next() as u8`

**Post-challenge messages are encrypted:**
- Sender encrypts XML with AES-128-ECB using session key
- Hex-encodes the ciphertext
- Sends hex string + null terminator
- Receiver hex-decodes, decrypts with same session key, parses XML

### Why Our Challenge Failed

We sent: `<LSX><Challenge key="..." version="3"/></LSX>\0`
Should be: `<LSX><Event><Challenge key="..."/></Event></LSX>\0`

The game's parser looks for `Message::Event` containing `EventBody::Challenge`.
Our message had `Challenge` as a direct child of `LSX`, which doesn't match the expected structure.

### Auth Code Request (GetAuthCode)

After challenge is accepted, the game sends (encrypted):
```xml
<LSX><Request recipient="EbisuSDK" id="N"><GetAuthCode/></Request></LSX>
```

Server responds (encrypted):
```xml
<LSX><Response id="N"><AuthCode Code="..." Type="0"/></Response></LSX>
```

### Next Steps

1. Fix the Origin IPC server to send the correct Challenge Event format
2. Implement AES-128-ECB crypto for the challenge handshake
3. Implement encrypted message handling for post-challenge communication
4. Handle GetAuthCode request and return a fake auth code
5. The game should then send SilentLogin to the Blaze server

### Key Source Files
- `github.com/ploxxxy/origin-sdk/src/crypto.rs` — AES-128-ECB encryption/decryption
- `github.com/ploxxxy/origin-sdk/src/random.rs` — Custom PRNG for key derivation
- `github.com/ploxxxy/origin-sdk/src/sdk.rs` — Connection, challenge flow, message handling
- `github.com/ploxxxy/origin-sdk/src/protocol/mod.rs` — All message types and XML structure
- `github.com/ploxxxy/origin-sdk/src/protocol/auth.rs` — ChallengeResponse, GetAuthCode, AuthCode

### Also Found
- `LSX-Dumper` by Warranty Voider: github.com/zeroKilo/LSX-Dumper — tool for dumping LSX protocol
- The protocol uses version "3" for encrypted communication
- Older protocol versions use the default key for ALL messages (no session key derivation)
