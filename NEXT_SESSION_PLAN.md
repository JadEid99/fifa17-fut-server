# FIFA 17 Private Server — Context Transfer (End of Day 5)

## GOAL
Revive FIFA 17 Ultimate Team by building a private Blaze server + DLL patches.

## ARCHITECTURE
- **Windows PC** (user's): Runs FIFA 17 game + DLL + server. Game at `D:\Games\FIFA 17\`
- **Mac** (Kiro): Edits code, pushes to git. User pulls and tests.
- **Git repo**: https://github.com/JadEid99/fifa17-fut-server.git
- **Ghidra export**: `/Users/jadeid/Downloads/ghidra/FIFA17_dumped.bin.c` (199MB, game base 0x140000000, NO ASLR)

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches (v106+Patch16)
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script for runtime tracing
- `batch_test_lsx.ps1` — Automated batch test (builds DLL, starts server, launches game)
- `batch-results.log` — Auto-logged server output

## BUILD & TEST
```
# Automated (recommended):
.\batch_test_lsx.ps1

# Manual build DLL (on Windows):
# batch_test_lsx.ps1 finds vcvars64.bat automatically

# Server-only changes: just restart server, no DLL rebuild needed
# DLL changes: need full game restart (use batch_test_lsx.ps1)
```

## CONNECTION PIPELINE — CURRENT STATUS

```
 1. DNS Redirect          ✅ hosts file: 127.0.0.1 winter15.gosredirector.ea.com
 2. Redirector TLS        ✅ Port 42230, TLS 1.2 + RC4-SHA handshake
 3. GetServerInstance      ✅ HTTP-over-TLS, returns 127.0.0.1:10041
 4. Main Server Connect    ✅ Plaintext (REDIRECT_SECURE=0)
 5. PreAuth                ✅ comp=0x0009 cmd=0x0007 (DLL Patch 8 bypasses handler)
 6. FetchClientConfig      ✅ 6 OSDK configs (CORE, CLIENT, NUCLEUS, WEBOFFER, ABUSE x2)
 7. Origin Online Check    ✅ DLL bypasses FUN_1470e0390
 8. Version Check          ✅ DLL bypasses FUN_1470da720 + FUN_145e280b0
 9. CreateAccount          ✅ DLL Patch 16 bypasses handler, state machine advances
10. OSDK Account Creation  ⚠️  Game shows account creation UI (stuck/loading)
11. Login                  ❌ BLOCKED by step 10
12. PostAuth               ❌ BLOCKED
13. Online Menu            ❌ BLOCKED
```

## BLAZE HEADER FORMAT (16 bytes, CONFIRMED & FIXED)

```
[0-3]   u32  payload length (big-endian)
[4-5]   u16  extended length (usually 0)
[6-7]   u16  component (big-endian)
[8-9]   u16  command (big-endian)
[10-12] u24  message ID (big-endian, 3 bytes) — used for RPC matching
[13]    u8   [type:3 bits (top)][flags:5 bits (bottom)]
[14-15] u16  error code (big-endian)
```

### Message types (byte13 >> 5):
- 0 (0x00-0x1F): Request
- 1 (0x20-0x3F): Response ← used for all our responses
- 2 (0x40-0x5F): Notification
- 3 (0x60-0x7F): Error response
- 4 (0x80-0x9F): Ping — game sends these, we echo back as pong

### Header fix (Day 5):
Server previously had error code at bytes 10-11 and msgId at wrong position.
Fixed: msgId at bytes 10-12, error at bytes 14-15. All responses use byte13=0x20.
This fixed RPC matching — FUN_146db5030 now finds pending RPCs correctly.

## CURRENT BOTTLENECK — OSDK ACCOUNT CREATION SCREEN

After CreateAccount succeeds, the game shows an OSDK account creation UI with:
- Broken localization strings (*TXT_OSDK_ACCOUNT_CREATION, *TXT_OSDK_CREATE_PERSONA)
- Email, password, country, DOB fields (NOT interactable — loading spinner active)
- Three radio buttons for data sharing preferences

### What triggers it:
The DLL's CreateAccount bypass (Patch 16) calls the state transition:
`(*(*(param_1[1]) + 8))(param_1[1], 1, 3)` — state 3 = OSDK account creation

### What we've tried:
- State 0: same OSDK screen
- State 4: same OSDK screen  
- No state transition (just RET): "EA servers not available" error
- Returning TOS/legal content for cmds 0xf2, 0xf6, 0x2f: screen still stuck loading
- Redirecting Nucleus URLs to local HTTP: no HTTP requests received (OSDK doesn't use HTTP)
- Removing 0x8c6 flag: screen still appears

### Blaze commands sent during OSDK screen:
1. `cmd=0x00F2` (GetLegalDocsInfo) — CTRY="", PTFM=4
2. `cmd=0x00F6` (GetTermsOfServiceContent) — CPFT=4, CTRY="", FTCH=1, LANG="", TEXT=0
3. `cmd=0x002F` (GetPrivacyPolicyContent) — same fields as 0xf6
4. Then just Ping packets (type=4) every ~3 seconds

### The loading spinner:
The UI shows a loading "17" icon, suggesting it's waiting for something.
Possible causes:
- Our TOS/legal responses have wrong TDF field names (we guessed LDVC/TCOL)
- The game needs specific TDF fields to populate the UI and make it interactable
- There's an additional request we're not seeing (maybe to Nucleus via HTTPS on port 443)

### Possible solutions (next session):
1. **Fix TOS/legal responses** — Use Frida to trace what the game does with our 0xf2/0xf6/0x2f responses. Find the correct TDF field names from Ghidra's response structure definitions.
2. **DLL bypass the OSDK UI** — Find the function that displays the account creation screen and NOP it. The game should then fall through to Login.
3. **Skip CreateAccount entirely** — Instead of patching FUN_146e151d0, patch the state machine to go directly from PreAuth to Login (skip CreateAccount + OSDK UI).
4. **Fake the Login flow** — After CreateAccount, instead of calling the state transition, directly call the Login handler (FUN_146e1c3f0) with fake data.

## DLL PATCHES (v106 + Patch 16)

| # | Target | What | Address |
|---|--------|------|---------|
| 1 | Cert verification | JNZ→JMP | Pattern scan |
| 2 | Origin SDK check | Always true | Pattern scan |
| 3 | FUN_1470db3c0 | Fake auth code provider | Pattern scan |
| 4 | Auth flag | [RBX+0x2061]=1 | Pattern scan |
| 5 | IsLoggedIntoEA | Always true | Pattern scan |
| 6 | IsLoggedIntoNetwork | Always true | Pattern scan |
| 7 | SDK gate + vtable checks | Return 1 | Fixed addresses |
| 8 | FUN_146e1cf10 (PreAuth handler) | Cave → calls FUN_146e1e460 | Fixed address |
| 9 | FUN_146e19a00 (PreAuth completion) | Immediate RET | Fixed address |
| 10 | FUN_1470e0390 (OriginCheckOnline) | Always return online | Fixed address |
| 11 | FUN_1470da720 (GetGameVersion) | Return 0 | Fixed address |
| 12 | FUN_145e280b0 (version compare) | Always match | Fixed address |
| 13 | GetProfileSync, GetSettingSync, SetPresence | Return 0 (delayed) | Fixed addresses |
| 14 | OnlineManager+0x13b8 | Force connState=0 continuously | Runtime |
| 15 | BlazeHub+0x53f | Force flag=1 continuously | Runtime |
| 16 | FUN_146e151d0 (CreateAccount handler) | Cave → state transition (1,3) | Fixed address |

## KEY GHIDRA FUNCTIONS

| Address | Name | Purpose |
|---------|------|---------|
| 0x146e1cf10 | PreAuth response handler | PATCHED: cave calls post_PreAuth |
| 0x146e19a00 | PreAuth completion | PATCHED: immediate RET |
| 0x146e1e460 | post_PreAuth (sends Ping) | Called by our cave |
| 0x146e1c3f0 | Login type processor | Never called (blocked by OSDK UI) |
| 0x146e151d0 | CreateAccount response handler | PATCHED: cave with state transition |
| 0x146db5a60 | RPC response dispatcher | Routes by message type |
| 0x146db5030 | RPC pending lookup | Matches msgId — NOW WORKING |
| 0x146db5d60 | RPC response decoder | Called after match — TDF decode fails (empty object) |
| 0x146db9270 | RPC response matcher | Uses (XOR & 0xf7ffffff)==0 |

## BLAZE COMPONENT COMMANDS (confirmed from traffic)

### Authentication (0x0001):
- 0x0A: CreateAccount ← WORKING (DLL bypass)
- 0x1D: ListUserEntitlements2
- 0x24: GetAuthToken
- 0x28: Login
- 0x29: AcceptTOS
- 0x2F: GetPrivacyPolicyContent ← game sends this after CreateAccount
- 0x30: ListPersonas
- 0x32: SilentLogin
- 0x3C: ExpressLogin
- 0x46: Logout
- 0x50: CreatePersona
- 0x64: ListPersonas
- 0x98: OriginLogin
- 0xF1: AcceptLegalDocs
- 0xF2: GetLegalDocsInfo ← game sends this after CreateAccount
- 0xF6: GetTermsOfServiceContent ← game sends this after CreateAccount

### Util (0x0009):
- 0x01: FetchClientConfig
- 0x02: Ping
- 0x07: PreAuth
- 0x08: PostAuth

## TDF ENCODING ISSUE (Day 5 finding)

The server's TDF encoder produces correct tags and types, but the game's RPC framework
doesn't decode the body into the response structure. Frida confirmed:
- Body data reaches FUN_146db5d60 (22 bytes, correct PNAM + UID TDF)
- vtable+0x30 creates the response object but fields are all zeros
- The response object vtable is 0x14389ac68 (CreateAccountResponse)
- Root cause unknown — possibly a TDF encoding subtlety or decoder state issue

This is why we use the DLL bypass (Patch 16) instead of relying on server TDF responses.

## WHAT THE GAME SENDS

### PreAuth request:
```
CDAT: { IITO=0, LANG=1701729619, SVCN="fifa-2017-pc-trial", TYPE=0 }
CINF: { BSDK="15.1.1.3.0", CLNT="FIFA17", CVER="3175939", DSDK="15.1.2.1.0", ENV="prod" }
FCCR: { CFID="BlazeSDK" }
```

### CreateAccount request:
```
AUTH = "FAKEAUTHCODE1234567890" (from DLL's fake auth code)
EXTB = (empty blob)
EXTI = 0
```

### After CreateAccount (with state 3):
```
GetLegalDocsInfo (0xF2): CTRY="", PTFM=4
GetTermsOfServiceContent (0xF6): CPFT=4, CTRY="", FTCH=1, LANG="", TEXT=0
GetPrivacyPolicyContent (0x2F): CPFT=4, CTRY="", FTCH=1, LANG="", TEXT=0
```

## ABANDONED APPROACHES
- Proactive server notifications (game ignores unsolicited packets)
- Various byte13 values for response type (0x00, 0x10, 0x80, 0xC0)
- Patching OSDK functions at startup (causes game hang)
- LSX Origin SDK server (game talks to STP via internal DLL, not external TCP)
- Brute-forcing state transition values (0, 3, 4 all show OSDK screen)
- Redirecting Nucleus URLs to local HTTP (OSDK doesn't make HTTP requests)
- Removing 0x8c6 flag (screen still appears regardless)
