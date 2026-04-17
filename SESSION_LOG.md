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


## WIRESHARK CAPTURE — GROUND TRUTH (April 17, 2026)

Successfully captured real Origin↔FIFA 17 IPC traffic on port 4216.

### Exact Protocol Format (from capture)

**Message 1: Origin → Game (Challenge) — 131 bytes**
```xml
<LSX><Event sender="EALS"><Challenge key="2b8ee7faea76e8a34f5f5d20e5328e32" build="release" version="10,4,13,6637"/></Event></LSX>\0
```
- `sender="EALS"` attribute on `<Event>`
- `build="release"` attribute on `<Challenge>`
- `version="10,4,13,6637"` (comma-separated, NOT just "3")
- Null terminator

**Message 2: Game → Origin (ChallengeResponse) — 381 bytes**
```xml
<LSX><Request recipient="EALS" id="1"><ChallengeResponse response="00b9c8afef744cbc1dd1b1e8aca6a2ed5fb0f43c5e287f833ea2750983772e0f954f64f2e4e86e9eee82d20216684899" key="dfbf4ba525f0c0c2da678381722206c2" version="3"><ContentId>1027460</ContentId><Title>FIFA 17</Title><MultiplayerId>1027460</MultiplayerId><Language/><Version>9.12.1.2</Version></ChallengeResponse></Request></LSX>\0
```
- `version="3"` on ChallengeResponse (protocol version, not SDK version)
- `response` = 96-char hex string (48 bytes encrypted with default key + PKCS7 padding)
- `key` = 32-char hex (16 bytes) — GAME's OWN key, different from Challenge key!
- Contains ContentId, Title, MultiplayerId, Language, Version (FIFA 17 uses 9.12.1.2)

**Message 3: Origin → Game (ChallengeAccepted) — 182 bytes**
```xml
<LSX><Response id="1" sender="EALS"><ChallengeAccepted response="65af7a2fdc8c63dc74c3382b1888608597b09acfb695e63466618d75ba992808954f64f2e4e86e9eee82d20216684899"/></Response></LSX>\0
```
- `sender="EALS"` on `<Response>`
- `response` = 96-char hex (likely encryption of game's key with default key, but with FIFA 17's custom variant)

**Messages 4+: ENCRYPTED, hex-encoded**
- Hex-encoded ASCII strings (e.g., "ee0a8c7c90b3...")
- Ciphertext length matches AES-128-ECB with PKCS7 padding
- BUT: Neither the origin-sdk session key derivation nor the default key decrypts these messages
- FIFA 17's Origin SDK 9.12.1.2 uses a DIFFERENT encryption scheme than v10.6.1.8

### Observations

1. **All encrypted messages from game end with same 15 bytes**: `...5711be57f994c06a1b303d9c0` — same padding block, suggests ECB mode confirmed
2. **Common prefixes** across same-direction messages (e.g., all game requests start similarly) — confirms ECB
3. **Messages 4+ have message IDs starting at 2 (first encrypted request after challenge)**
4. The game's ChallengeResponse `key` attribute (`dfbf4b...`) is DIFFERENT from the Challenge's `key` (`2b8ee7...`) — the game generates its own key for the session

### Mystery: The Session Key Derivation

The origin-sdk crate derives the session key from the first 2 bytes of the response hex string interpreted as ASCII:
- `response = "00b9c8..."` → ASCII bytes `0x30 0x30` → seed `0x3030 = 12336`

Applying this to FIFA 17's response `"00b9c8afef..."` gives seed 12336, but decryption fails. FIFA 17 must use:
- A different key derivation algorithm
- OR a different encryption mode (CBC? with different IV?)
- OR encryption on the HEX STRING itself (treating ASCII hex as plaintext)

### Files Available
- `origin_capture.pcapng` — full Wireshark capture
- Contains complete handshake + ~30 encrypted messages

### NEXT STEP: Decrypt the post-challenge messages

To emulate Origin properly, we need to understand the encryption. Options:
1. Reverse-engineer the crypto from FIFA 17's binary (find the encrypt/decrypt functions in Ghidra)
2. Use a known-plaintext attack (we know the XML structure — try all plausible keys)
3. Look for the LSX-Dumper tool source code which may have FIFA-era protocol details


---

# SESSION 2 — April 17, 2026 (continued)

## CRYPTO BREAKTHROUGH: Session Key Derivation SOLVED

### The Problem
After the ChallengeAccepted handshake, all subsequent Origin IPC messages are AES-128-ECB encrypted, hex-encoded, null-terminated. The origin-sdk Rust crate (v10.6.1.8) derives the session key from the first 2 ASCII chars of the CLIENT's ChallengeResponse `response` field. This did NOT work for FIFA 17 (Origin SDK v9.12.1.2).

### The Solution: Known-Plaintext Attack
We knew that all game→Origin encrypted messages start with the same 16-byte ciphertext block (`ee0a8c7c90b3738b61f520e33e1bb920`). We also knew the plaintext MUST be `<LSX><Request re` (16 ASCII bytes = 1 AES block).

**Method:** Brute-forced all 65536 possible u16 seeds (0-65535) through the origin-sdk PRNG key derivation, generated the AES key for each, and tested whether decrypting the known ciphertext block produced the known plaintext.

**Result:** Seed **13877** (variant A, origin-sdk algorithm) produces key `f27f5c27d11e0bb8831c11e778fe71f7`, which correctly decrypts ALL messages in both directions.

### The Key Insight: Seed Source is ChallengeAccepted, NOT ChallengeResponse

- **origin-sdk v10.6.1.8:** seed = ASCII of first 2 chars of ChallengeResponse's `response` field (CLIENT's encrypted challenge key)
- **FIFA 17 v9.12.1.2:** seed = ASCII of first 2 chars of ChallengeAccepted's `response` field (SERVER's encrypted client key)

Both sides can compute this because:
1. Client sends its `key` attribute in ChallengeResponse
2. Server encrypts client's key with default key [0..15] → ChallengeAccepted `response`
3. Client can also compute this encryption (it knows its own key + the default key)
4. Both sides take first 2 hex chars of that encrypted value as ASCII → seed

**Proof from Wireshark capture:**
- ChallengeAccepted response starts with `"65af7a..."` 
- ASCII of `'6'` = 0x36, ASCII of `'5'` = 0x35
- Seed = (0x36 << 8) | 0x35 = **13877**
- deriveKey(13877) = `f27f5c27d11e0bb8831c11e778fe71f7` ✅

### Verification: Complete Protocol Decrypted

Using the derived session key, we decrypted ALL 18+ messages from the Wireshark capture. Every single one produced valid XML:

```
O->G [PLAIN] Challenge (key=2b8ee7...)
G->O [PLAIN] ChallengeResponse (response=00b9c8..., key=dfbf4b...)
O->G [PLAIN] ChallengeAccepted (response=65af7a...)
G->O [ENC]   <LSX><Request recipient="EbisuSDK" id="2"><GetConfig version="3"/></Request></LSX>
O->G [ENC]   <LSX><Response id="2" sender="EbisuSDK"><GetConfigResponse Config="false"/></Response></LSX>
G->O [ENC]   <LSX><Request recipient="" id="3"><GetProfile index="0" version="3"/></Request></LSX>
O->G [ENC]   <LSX><Response id="3" sender="EbisuSDK"><GetProfileResponse IsSubscriber="true" PersonaId="33068179" .../>
G->O [ENC]   GetSetting IS_IGO_ENABLED → "false"
G->O [ENC]   GetGameInfo FREETRIAL → "false"
G->O [ENC]   GetGameInfo LANGUAGES → "ar_SA,cs_CZ,da_DK,de_DE,en_US,..."
G->O [ENC]   GetSetting ENVIRONMENT → "production"
G->O [ENC]   GetSetting IS_IGO_AVAILABLE → "false"
G->O [ENC]   IsProgressiveInstallationAvailable → Available="false"
G->O [ENC]   GetProfile (repeated)
G->O [ENC]   GetSetting LANGUAGE → "en_US"
G->O [ENC]   GetGameInfo FREETRIAL → "false"
G->O [ENC]   SetDownloaderUtilization → ErrorSuccess
G->O [ENC]   GetSetting ENVIRONMENT → "production"
G->O [ENC]   GetInternetConnectedState → connected="0"
G->O [ENC]   GetProfile (third time)
```

### Exact Response Formats (Ground Truth from Capture)

These are the EXACT XML formats the real Origin server used:

| Request | Response Format |
|---------|----------------|
| GetConfig | `<GetConfigResponse Config="false"/>` |
| GetProfile | `<GetProfileResponse IsSubscriber="true" PersonaId="33068179" AvatarId="" Country="US" CommerceCountry="US" GeoCountry="US" UserId="33068179" Persona="Player" IsUnderAge="false" CommerceCurrency="USD"/>` |
| GetSetting | `<GetSettingResponse Setting="VALUE"/>` (NOT `SettingId=`/`Value=`) |
| GetGameInfo | `<GetGameInfoResponse GameInfo="VALUE"/>` |
| GetInternetConnectedState | `<InternetConnectedState connected="0"/>` |
| IsProgressiveInstallationAvailable | `<IsProgressiveInstallationAvailableResponse ItemId="" Available="false"/>` |
| SetDownloaderUtilization | `<ErrorSuccess Code="0" Description=""/>` |

### Implementation

Updated `server-standalone/origin-ipc-server.mjs` (v5) with:
1. Correct session key derivation from ChallengeAccepted response
2. All response formats matching Wireshark ground truth
3. Full AES-128-ECB encrypt/decrypt for post-challenge messages
4. Verified end-to-end with automated test (ChallengeAccepted matches byte-for-byte, session key matches)

### Impact

**Game freeze PERMANENTLY FIXED.** Before this breakthrough, the game froze at the language selection screen because the Origin SDK's recv() blocked the main thread waiting for valid encrypted data. With correct crypto, the SDK completes its full init sequence (13+ messages) and the game proceeds normally.

---

## PHASE 10: Post-Crypto — Blaze Authentication Bottleneck

### What Works Now
| Step | Status |
|------|--------|
| Origin IPC Challenge/Response | ✅ Full crypto working |
| Origin IPC GetConfig/GetProfile/GetSetting | ✅ All 13 messages served |
| Game launches past language screen | ✅ No more freeze |
| TLS Redirector handshake | ✅ |
| Blaze PreAuth | ✅ |
| 6x FetchClientConfig | ✅ |
| DLL Patch 3 (fake auth code) | ✅ Cave executes, req[+0xe8]=1 |

### Current Bottleneck
After completing Origin IPC init + Blaze PreAuth + FetchClientConfig, the game sends **Logout (comp=0x0001 cmd=0x0046) with empty body** as its FIRST authentication command. It never sends CreateAccount, Login, SilentLogin, or OriginLogin.

The "EA servers are not available" error message appears on screen.

### What We Tried (All Failed)

1. **Changed PersonaId to real value (33068179)** — No change. Game still sends Logout.

2. **Proactive SilentLogin notification from Blaze server** — Sent `comp=0x0001 cmd=0x0032 notify=true` with full SESS/PDTL struct after PreAuth. Game ignored it, still sent Logout.

3. **Pushed `<Login IsLoggedIn="true"/>` event via Origin IPC** — Sent encrypted `<LSX><Event sender="EALS"><Login IsLoggedIn="true"/></Event></LSX>` after ChallengeAccepted. Event was delivered (confirmed in logs). Game still sent Logout.

4. **Fixed Blaze ping reply type** — Changed pong type byte from 0x80 (PING) to 0xA0 (PING_REPLY). Correct fix but not the core issue.

5. **Fixed Logout handler** — Separated Logout from Login handler, returns empty ack instead of full session payload. Correct fix but not the core issue.

6. **Enhanced CreateAccount handler** — Returns full SessionInfo (SESS struct with BUID, PDTL, etc.). Never reached because game sends Logout, not CreateAccount.

### Ghidra Analysis: Why Logout?

**FUN_146f199c0** (FirstPartyAuthTokenRequest processor):
- Called from `FUN_146f7c7e0` (online tick, every frame)
- Iterates 2 auth request slots at `OnlineMgr+0x4e98`
- For each non-null slot: calls `FUN_1470db3c0` (OriginRequestAuthCodeSync)
- If auth code returned: copies to buffer, sets `req[+0xe8]=1`
- DLL Patch 3 short-circuits `FUN_1470db3c0` to return fake auth code instantly

**The auth code IS being delivered** (DLL log confirms `CAVE EXECUTED`, `req[+0xe8]=1`). But the game's upper layer still chooses Logout.

**FUN_147102800** (Origin SDK Login event dispatcher):
- Found in Ghidra: dispatches on `<Login>` tag with `sender="EALS"` 
- Calls `FUN_147138640` which reads `IsLoggedIn` attribute
- Sets internal Origin SDK `IsLoggedIn` flag
- We pushed this event but game still sent Logout

### Theories for Why Logout Persists

1. **The `<Login>` event format may need additional attributes** beyond `IsLoggedIn="true"`. The game might need `SessionInformation`, `UserId`, or other fields to fully transition to "logged in" state.

2. **The `<Login>` event might need to be a `<Command>` not an `<Event>`** — different LSX message types have different dispatch paths.

3. **The auth code injection via slot is too late** — by the time the DLL's polling loop injects the fake request (6 seconds after startup), the game's online state machine has already decided "no auth available" and queued the Logout. The auth code arrives but the decision was already made.

4. **FIFA 17's online layer has a SEPARATE "is user logged into Origin" check** that reads from the Origin SDK object directly (not from the `<Login>` event). This check might look at a field we haven't set.

5. **The game expects `GetAuthCode` to be called via LSX** (not via DLL patch). The natural flow would be: game calls `FUN_1470db3c0` → LSX `GetAuthCode` → Origin server returns auth code → game uses it for Blaze login. Our DLL patch bypasses the LSX call entirely, which might skip setting some internal state that the Blaze login path checks.

### Recommended Next Steps

1. **Try the LSX GetAuthCode path instead of DLL Patch 3**: Disable Patch 3, let `FUN_1470db3c0` call through to `FUN_1470e67f0` which sends LSX `GetAuthCode`. Our Origin IPC server already handles this and returns a fake auth code. This is the "natural" flow and might set all required internal state.

2. **Capture what happens when `FUN_1470e2840()` is called**: This function returns `DAT_144b7c7a0 != 0` (Origin SDK object exists). If it returns false, `FUN_1470db3c0` errors out without calling LSX. Add Frida hook to trace this.

3. **Hook `FUN_146f199c0` with Frida** to see if it's even being called, and if so, what the slot values are when it runs.

4. **Try sending `<Login>` with more attributes**: Add `UserId`, `PersonaId`, `SessionInformation` to the Login event.

5. **Look at PocketRelay's client plugin** (ASI for ME3) to see how they handle the Origin auth bypass — they might patch at a different level.

6. **Try `-webMode SP`** in commandline.txt to see if single-player mode bypasses the auth entirely and lets us reach the main menu.

---

## FILES (Current State)

| File | Purpose | Status |
|------|---------|--------|
| `server-standalone/origin-ipc-server.mjs` | Fake Origin IPC server (v5) | ✅ Working — full crypto, all responses |
| `server-standalone/server.mjs` | Blaze server (TLS + plaintext) | ✅ Working — PreAuth, FetchClientConfig, proactive SilentLogin |
| `dll-proxy/dinput8_proxy.cpp` | DLL proxy (v97) | ✅ Working — all patches including Patch 3 re-enabled |
| `origin_capture.pcapng` | Wireshark ground truth | Reference data |
| `batch_test_lsx.ps1` | Main test script | ✅ Starts both servers, collects all logs |
| `commandline.txt` | Game launch args | Contains -authCode (unused by game) |

## KEY ADDRESSES (Ghidra, base 0x140000000)

| Address | Function | Notes |
|---------|----------|-------|
| `0x1470db3c0` | OriginRequestAuthCodeSync | Patched by DLL Patch 3 |
| `0x1470e67f0` | Origin SDK RequestAuthCode (LSX sender) | Sends GetAuthCode via LSX |
| `0x1470e2840` | IsOriginSDKConnected | Returns `DAT_144b7c7a0 != 0` |
| `0x144b7c7a0` | Origin SDK object pointer | Set during SDK init, cleared on destroy |
| `0x146f199c0` | FirstPartyAuthTokenRequest processor | Per-frame tick, processes auth slots |
| `0x146f7c7e0` | Online tick (main loop) | Calls auth processor + other online logic |
| `0x147102800` | Login event dispatcher (Origin SDK) | Dispatches `<Login>` events from server |
| `0x147138640` | Login event parser | Reads `IsLoggedIn` attribute |
| `0x146e1cf10` | PreAuth response handler | Patched to always-success |
| `0x146e19a00` | PreAuth completion/cleanup | Patched to immediate RET |


---

## ADDITIONAL TECHNICAL DETAILS (Session 2)

### ChallengeAccepted Response Field — Verified

The ChallengeAccepted `response` attribute = `AES-128-ECB(client's 32-char hex key as ASCII string, default key [0..15])`.

**Proof:** From Wireshark capture:
- Client's key: `dfbf4ba525f0c0c2da678381722206c2`
- Expected ChallengeAccepted response: `65af7a2fdc8c63dc74c3382b1888608597b09acfb695e63466618d75ba992808954f64f2e4e86e9eee82d20216684899`
- `AES-ECB-Encrypt("dfbf4ba525f0c0c2da678381722206c2", [0,1,2,...,15])` = exact match ✅

### PKCS7 Padding Block Observation

Both ChallengeResponse and ChallengeAccepted `response` fields (96 hex chars = 48 bytes = 3 AES blocks) end with the SAME 32 hex chars: `954f64f2e4e86e9eee82d20216684899`. This is the AES-ECB encryption of a 16-byte PKCS7 padding block (`[0x10, 0x10, ..., 0x10]`) with the default key. Since AES-ECB is deterministic, the same padding block always produces the same ciphertext. This confirms both sides use the same default key for the challenge handshake.

### PRNG Algorithm (Exact Implementation)

```javascript
function createRng(seed) {
  let s = seed >>> 0;  // unsigned 32-bit
  return {
    next() {
      s = ((s * 214013) + 2531011) >>> 0;  // MSVC LCG constants
      return (s >>> 16) & 32767;            // bits 16-30
    },
    setSeed(ns) { s = ns >>> 0; }
  };
}

function deriveKey(seed) {
  if (seed === 0) return Buffer.from([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
  const rng = createRng(7);           // initial seed = 7
  const newSeed = (rng.next() + seed) >>> 0;  // rng(7).next() = 61, so newSeed = seed + 61
  rng.setSeed(newSeed);
  const key = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) key[i] = rng.next() & 0xFF;
  return key;
}
```

Constants: MULTIPLIER=214013 (0x343FD), INCREMENT=2531011 (0x269EC3), RAND_MAX=32767 (0x7FFF). These are the Microsoft Visual C++ LCG constants.

### `-authCode` Command Line Argument

Searched the Ghidra dump for `authCode` / `auth_code` / `-authCode` — **no command-line parser for this exists in FIFA 17**. The BF4 Blaze emulator uses `-authCode noneed` but FIFA 17 does not support this argument. The `commandline.txt` entry `-authCode FAKEAUTHCODE1234567890` has no effect.

### Blaze Protocol Message Type Byte Encoding

Byte 13 of the 16-byte Blaze header encodes the message type in the top 3 bits:

| Byte Value | Top 3 Bits | Type | Meaning |
|------------|-----------|------|---------|
| 0x00 | 000 | 0 | MESSAGE (request) |
| 0x20 | 001 | 1 | REPLY (response) |
| 0x40 | 010 | 2 | NOTIFICATION (server push) |
| 0x60 | 011 | 3 | ERROR_REPLY |
| 0x80 | 100 | 4 | PING |
| 0xA0 | 101 | 5 | PING_REPLY |

Our server was incorrectly responding to PING (0x80) with another PING (0x80) instead of PING_REPLY (0xA0). Fixed in this session.

### Blaze Session Sequence (Observed in Every Test)

Every test run since the crypto fix shows this exact sequence on the plaintext Blaze server (port 10041):

```
Session 1:
  1. PreAuth (comp=0x0009 cmd=0x0007) → 628-byte response
  2. Ping (comp=0x0009 cmd=0x0002) → pong
  3. FetchClientConfig "OSDK_CORE" → 5 entries
  4. FetchClientConfig "OSDK_CLIENT" → 4 entries
  5. FetchClientConfig "OSDK_NUCLEUS" → 3 entries
  6. FetchClientConfig "OSDK_WEBOFFER" → 1 entry
  7. FetchClientConfig "OSDK_ABUSE_REPORTING" → 1 entry
  8. FetchClientConfig "OSDK_XMS_ABUSE_REPORTING" → 1 entry
  9. Low-level PING (type=4, comp=0 cmd=0) → PING_REPLY
  10. Logout (comp=0x0001 cmd=0x0046 len=0) → empty ack
  11. Disconnect

Sessions 2-N:
  Each sends a single PING (type=4) packet, gets PING_REPLY, disconnects.
  These are the game's reconnection attempts (every ~15s).
```

### Origin IPC Session Sequence (Observed in Every Test)

```
1. Server → Game: Challenge (plaintext)
2. Game → Server: ChallengeResponse (plaintext)
3. Server → Game: ChallengeAccepted (plaintext)
4. Server → Game: Login event IsLoggedIn=true (encrypted) [added in session 2]
5. Game → Server: GetConfig (encrypted) → GetConfigResponse
6. Game → Server: GetProfile index=0 (encrypted) → GetProfileResponse
7. Game → Server: GetSetting IS_IGO_ENABLED → "false"
8. Game → Server: GetGameInfo FREETRIAL → "false"
9. Game → Server: GetSetting ENVIRONMENT → "production"
10. Game → Server: GetSetting IS_IGO_AVAILABLE → "false"
11. Game → Server: IsProgressiveInstallationAvailable → Available="false"
12. Game → Server: GetProfile index=0 (repeat)
13. Game → Server: GetSetting LANGUAGE → "en_US"
14. Game → Server: SetDownloaderUtilization → ErrorSuccess
15. Game → Server: GetSetting ENVIRONMENT (repeat) → "production"
```

Note: Game NEVER sends GetAuthCode via LSX. This is because DLL Patch 3 short-circuits `FUN_1470db3c0` before it reaches the LSX send path.

### "FIFA 17 is shutting down" Popup

This external Windows popup appears when the test script kills the node processes at the end of the test. The Origin IPC socket closes, and the game's Origin SDK detects "Origin client was terminated." This is a cosmetic side-effect of test teardown, not a bug in our implementation.

### `origin_format_test.ps1` vs `batch_test_lsx.ps1`

- `origin_format_test.ps1` — Older test script that sets `CHALLENGE_FORMAT` env var. Was used during Phase 6-7 when testing different Challenge XML formats. **This script was associated with the game freeze issue** because it was used before the crypto breakthrough.
- `batch_test_lsx.ps1` — Current primary test script. Starts both Blaze server and Origin IPC server, builds DLL, launches game, navigates menus, collects all logs (Origin IPC + Blaze + DLL). **This is the script that should be used for all testing.**

### PocketRelay Reference (ME3 Blaze Server)

PocketRelay (github.com/PocketRelay/Server) is a Rust implementation of the ME3 multiplayer Blaze server. Key findings from their source:

- **OriginLoginRequest**: `{ AUTH: "ORIGIN_AUTH_TOKEN", TYPE: 1 }` — cmd 0x98 on component 0x0001
- **SilentLoginRequest**: `{ AUTH: "AUTH_TOKEN", PID: player_id, TYPE: 2 }` — cmd 0x0032
- **LoginRequest**: `{ MAIL: "email", PASS: "password", TYPE: 0 }` — cmd 0x0028
- **AuthResponse** (for all login types): Contains AGUP, LDHT, NTOS, PCTK (session token), PRIV, SESS struct (BUID, FRST, KEY, LLOG, MAIL, PDTL, UID), SPAM, THST, TSUI, TURI
- ME3 uses the same Blaze SDK version family as FIFA 17

### Origin SDK Object Lifecycle (Ghidra)

- **FUN_1470e07b0**: Creates Origin SDK object. Allocates 0x3c8 bytes, calls `FUN_1470de960` to initialize, stores pointer in `DAT_144b7c7a0`, then calls `FUN_1470e5770` to initiate TCP connection.
- **FUN_1470df860**: Destroys Origin SDK object. Sets `DAT_144b7c7a0 = 0`, cleans up all internal state.
- **FUN_1470e2840**: Returns `DAT_144b7c7a0 != 0` — used as "is SDK connected" check by all Origin API functions. If false, all Origin calls (GetProfile, GetAuthCode, etc.) bail out with error `0xa0010000`.

### GetInternetConnectedState Discrepancy

In the real Wireshark capture, Origin returned `connected="0"` (user was offline/not signed in). Our server returns `connected="1"`. This might matter — if the game interprets `connected="1"` as "internet available, should be able to reach EA servers" but then can't, it might trigger the "EA servers unavailable" error. Worth testing with `connected="0"`.

### DLL Patch Timeline (Typical Run)

```
T+0ms:     DllMain — fake SDK object created
T+150ms:   Patch 1: cert bypass
T+350ms:   Patch 3: FUN_1470db3c0 body → fake auth code
T+400ms:   Patch 4: auth flag
T+450ms:   Patches 5-6: IsLoggedIntoEA/Network → true
T+500ms:   Patch 7: SDK gate, login vtable, PreAuth handler
T+500ms:   Connect hook: DAT_148e223d8 patched
T+500ms:   Origin online check, version patches
T+800ms:   Origin SDK connect redirected 4216→3216
T+5600ms:  Auth slot cleared, fake request injected
T+5700ms:  Cave executed, auth code delivered (req[+0xe8]=1)
T+5700ms:  Post-load OSDK patches applied
```

The 5.6-second gap between patches completing and auth slot clearing is the DLL's polling loop waiting for the game's initial auth request to complete/clear before injecting the fake one.
