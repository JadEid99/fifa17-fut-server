# FIFA 17 Private Server — Context Transfer (End of Day 4)

## GOAL
Revive FIFA 17 Ultimate Team by building a private Blaze server + DLL patches.

## ARCHITECTURE
- **Windows PC** (user's): Runs FIFA 17 game + DLL + server. Game at `D:\Games\FIFA 17\`
- **Mac** (Kiro): Edits code, pushes to git. User pulls and tests.
- **Git repo**: https://github.com/JadEid99/fifa17-fut-server.git
- **Ghidra export**: `/Users/jadeid/Downloads/ghidra/FIFA17_dumped.bin.c` (199MB, game base 0x140000000, NO ASLR)

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches (v106)
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script for runtime tracing
- `frida_test.ps1` — Automated Frida test (builds DLL, starts server, launches game, attaches Frida)
- `batch_test_lsx.ps1` — Automated batch test (no Frida)
- `batch-results.log` — Auto-logged server output (server writes on disconnect, user pushes manually)

## BUILD & TEST
```
# Build DLL (on Windows):
cmd /c "vcvars64.bat && cd dll-proxy && cl /LD /O2 /EHsc dinput8_proxy.cpp /Fe:dinput8.dll /link /DEF:dinput8.def user32.lib ws2_32.lib"
# Deploy: copy dll-proxy\dinput8.dll to D:\Games\FIFA 17\dinput8.dll

# Start server:
node --openssl-legacy-provider --security-revert=CVE-2023-46809 server-standalone\server.mjs

# Server-only changes: just restart server, press Q in game
# DLL changes: need full game restart (use batch_test_lsx.ps1)
```

## CONNECTION PIPELINE — CURRENT STATUS

```
 1. DNS Redirect          ✅ hosts file: 127.0.0.1 winter15.gosredirector.ea.com
 2. Redirector TLS        ✅ Port 42230, TLS 1.2 + RC4-SHA handshake
 3. GetServerInstance     ✅ HTTP-over-TLS, returns 127.0.0.1:10041
 4. Main Server Connect   ✅ Plaintext (REDIRECT_SECURE=0)
 5. PreAuth               ✅ comp=0x0009 cmd=0x0007
 6. FetchClientConfig     ✅ 6 OSDK configs (CORE, CLIENT, NUCLEUS, WEBOFFER, ABUSE x2)
 7. Origin Online Check   ✅ DLL bypasses FUN_1470e0390
 8. Version Check         ✅ DLL bypasses FUN_1470da720 + FUN_145e280b0
 9. CreateAccount         ⚠️  Game sends cmd=0x000A, we respond, game sends Logout
10. Login                 ❌ BLOCKED
11. PostAuth              ❌ BLOCKED
12. Online Menu           ❌ BLOCKED
```

## BLAZE HEADER FORMAT (16 bytes, CONFIRMED)

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
- 1 (0x20-0x3F): Response ← CONFIRMED from Ghidra FUN_146db5a60
- 2 (0x40-0x5F): Notification
- 3 (0x60-0x7F): Error response
- 4 (0x80-0x9F): Ping/Special
- 5 (0xA0-0xBF): Acknowledgment

### Current response format:
- Util component (0x0009): byte13=0x20 (Response type) — WORKS
- Auth component (0x0001): byte13=0x20 — game accepts but TDF body NOT parsed
- byte13=0x40 (Notification) — game accepts but TDF body NOT parsed
- byte13=0x00 (Request) — RPC timeout, game ignores

### RPC matching (Ghidra FUN_146db5030):
Matches on: `pending.field_0x30 == param_2 AND pending.field_0x38 == param_3`
The match uses message ID from bytes 10-12 of the header.

## CURRENT BOTTLENECK

The CreateAccount response handler (FUN_146e151d0) is called with param3=0 (success) when using byte13=0x20. But the TDF body is NOT parsed — the response structure has all zeros at offsets +0x10 through +0x13.

The handler checks `*(param2 + 0x13) != 0` for the success path. Since it's 0, the game doesn't proceed.

### CreateAccountResponse has 2 TDF fields (confirmed from Ghidra field table at 0x144878060):
1. **PNAM** (string) at struct offset 0x18 — Persona Name
2. **UID** (integer) at struct offset 0x10 — User ID (must be non-zero)

### Why TDF isn't parsed:
byte13=0x20 goes through FUN_146db5a60 as type 1 (Response). It calls FUN_146db5030 to find the pending RPC. But FUN_146db5030 returns NULL — no matching pending RPC found. So the response body is dropped.

The pending RPC lookup matches on message ID + connection pointer. Our message ID (from bytes 10-12) might not match the game's internal ID.

### Possible solutions:
1. **Fix the message ID matching** — figure out what ID the game assigns to the CreateAccount RPC and echo it correctly
2. **DLL bypass** — patch FUN_146e151d0 to always take the success path with hardcoded values (like we did for PreAuth with FUN_146e1cf10)
3. **Frida injection** — use Frida to write the correct values into the response structure at runtime

## DLL PATCHES (v106, dinput8_proxy.cpp)

| # | Target | What | Address |
|---|--------|------|---------|
| 1 | Cert verification | JNZ→JMP | 0x14613244B (pattern scan) |
| 2 | Origin SDK check | Always true | 0x1470A8430 (pattern scan) |
| 3 | FUN_1470db3c0 | Fake auth code provider | Pattern scan |
| 4 | Auth flag | [RBX+0x2061]=1 | Pattern scan |
| 5 | IsLoggedIntoEA | Always true | Pattern scan |
| 6 | IsLoggedIntoNetwork | Always true | Pattern scan |
| 7 | SDK gate (FUN_1471a5da0) | Always return 1 | Fixed address |
| 7b | Login vtable checks | Return 1 | Fixed vtable addresses |
| 8 | FUN_146e1cf10 (PreAuth handler) | Cave → calls FUN_146e1e460 | Fixed address |
| 9 | FUN_146e19a00 (PreAuth completion) | Immediate RET | Fixed address |
| 10 | FUN_1470e0390 (OriginCheckOnline) | Always return online | Fixed address |
| 11 | FUN_1470da720 (GetGameVersion) | Return 0 | Fixed address |
| 12 | FUN_145e280b0 (version compare) | Always match | Fixed address |
| 13 | GetProfileSync, GetSettingSync, SetPresence | Return 0 (delayed, after auth injection) | Fixed addresses |
| 14 | OnlineManager+0x13b8 | Force connState=0 continuously | Runtime |
| 15 | BlazeHub+0x53f | Force flag=1 continuously | Runtime |

## KEY GHIDRA FUNCTIONS

| Address | Name | Purpose |
|---------|------|---------|
| 0x146e1cf10 | PreAuth response handler | PATCHED: cave calls post_PreAuth |
| 0x146e19a00 | PreAuth completion | PATCHED: immediate RET |
| 0x146e1e460 | post_PreAuth (sends Ping) | Called by our cave |
| 0x146e1c3f0 | Login type processor | Never called (needs PreAuth response data) |
| 0x146e151d0 | CreateAccount response handler | Called with param3=0 but TDF not parsed |
| 0x146db5a60 | RPC response dispatcher | Routes by message type |
| 0x146db5030 | RPC pending lookup | Matches msgId + connection ptr |
| 0x146db9270 | RPC response matcher | Uses (XOR & 0xf7ffffff)==0 |
| 0x1470e0390 | OriginCheckOnline | PATCHED: always online |
| 0x1470da720 | GetGameVersion | PATCHED: return 0 |
| 0x1470da970 | GetProfileSync | PATCHED: return 0 (delayed) |
| 0x1470daa30 | GetSettingSync | PATCHED: return 0 (delayed) |
| 0x1470db760 | SetPresence | PATCHED: return 0 (delayed) |

## BLAZE COMPONENT COMMANDS (from PocketRelay)

### Authentication (0x0001):
- 0x0A: CreateAccount
- 0x1D: ListUserEntitlements2
- 0x24: GetAuthToken
- 0x28: Login
- 0x30: ListPersonas
- 0x32: SilentLogin
- 0x3C: ExpressLogin
- 0x46: Logout
- 0x64: ListPersonas
- 0x98: OriginLogin

### Util (0x0009):
- 0x01: FetchClientConfig
- 0x02: Ping
- 0x07: PreAuth
- 0x08: PostAuth

### UserSessions (0x7802):
- 0x0001: UserSessionExtendedDataUpdate (notification)
- 0x0014: UpdateNetworkInfo

## WHAT THE GAME SENDS

### PreAuth request:
```
CDAT: { IITO=0, LANG=1701729619, SVCN="fifa-2017-pc", TYPE=0 }
CINF: { BSDK="15.1.1.3.0", CLNT="FIFA17", CVER="3175939", DSDK="15.1.2.1.0", ENV="prod" }
FCCR: { CFID="BlazeSDK" }
```

### CreateAccount request:
```
AUTH = "FAKEAUTHCODE1234567890" (from DLL's fake auth code)
EXTB = (empty blob)
EXTI = 0
```

### FetchClientConfig requests (6 total):
OSDK_CORE, OSDK_CLIENT, OSDK_NUCLEUS, OSDK_WEBOFFER, OSDK_ABUSE_REPORTING, OSDK_XMS_ABUSE_REPORTING

## ABANDONED APPROACHES
- Proactive server notifications (game ignores unsolicited packets)
- Various byte13 values for response type (0x00, 0x10, 0x80, 0xC0 — all fail for different reasons)
- Patching OSDK functions at startup (causes game hang — they're needed during loading)
- LSX Origin SDK server (game talks to STP via internal DLL, not external TCP)

## NEXT STEPS
1. Figure out why FUN_146db5030 (RPC lookup) returns NULL for our CreateAccount response
2. OR: Patch FUN_146e151d0 from DLL to bypass the TDF parsing and hardcode success values
3. OR: Use Frida to write userId into the response structure at runtime
