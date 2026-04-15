# FIFA 17 Private Server — Context Transfer (End of Day 5)

## GOAL
Revive FIFA 17 Ultimate Team by building a private Blaze server + DLL patches.

## ARCHITECTURE
- **Windows PC** (user's): Runs FIFA 17 game + DLL + server. Game at `D:\Games\FIFA 17\`
- **Mac** (Kiro): Edits code, pushes to git. User pulls and tests.
- **Git repo**: https://github.com/JadEid99/fifa17-fut-server.git
- **Ghidra export**: `/Users/jadeid/Downloads/ghidra/FIFA17_dumped.bin.c` (199MB, game base 0x140000000, NO ASLR)

## KEY FILES
- `dll-proxy/dinput8_proxy.cpp` — DLL with all patches
- `server-standalone/server.mjs` — Node.js Blaze server
- `frida_force_login.js` — Frida script for runtime tracing
- `batch_test_lsx.ps1` — Automated batch test (builds DLL, starts server, launches game)
- `frida_test.ps1` — Automated Frida test (same + attaches Frida)
- `batch-results.log` — Auto-logged server output

## BUILD & TEST
```
# Automated (recommended):
.\batch_test_lsx.ps1       # No Frida, faster
.\frida_test.ps1           # With Frida tracing

# Server-only changes: just restart server, no DLL rebuild needed
# DLL changes: need full game restart (use batch_test_lsx.ps1)
```

## IMMEDIATE PRIORITY — BYPASS ACCOUNT CREATION WITH PRE-MADE ACCOUNTS

The server will have pre-created accounts in a config file. Each player has a username,
password, persona name, and UID. The game should never show the account creation screen —
it should accept the pre-configured account and proceed to Login.

### Architecture:
- Server config file with pre-made accounts (username, password, persona, UID)
- When game sends CreateAccount, server responds with the pre-configured account data
- DLL makes the game accept this and skip OSDK account creation UI
- Game proceeds to Login → PostAuth → Online Menu

### The blocker:
The CreateAccount response TDF wasn't being decoded (0 bytes consumed). The game's handler
saw UID=0 at +0x13, which triggered the "needs persona creation" path (OSDK screen).

### FIX APPLIED (Day 6):
1. **Server**: CreateAccount response now sends full AuthResponse (same as Login):
   AGUP, LDHT, NTOS, PCTK, PRIV, SESS{BUID, FRST, KEY, LLOG, MAIL, PDTL{DSNM, LAST, PID, STAS, XREF, XTYP}, UID}, SPAM, THST, TSUI, TURI
   Previously was sending just PNAM + UID (wrong structure — not what the decoder expects).
   
2. **DLL Patch 16**: Changed from "bypass handler entirely" to "trampoline that forces R8D=0
   (success) then runs original handler code" — same approach as PreAuth (Patch 8).
   The original handler will now process the correctly-decoded TDF response and advance
   the state machine naturally.

3. **Server**: Fixed TOS/legal responses to match PocketRelay format:
   - GetLegalDocsInfo (0xF2): EAMC(int), LHST(str), PMC(int), PPUI(str), TSUI(str)
   - GetTermsOfServiceContent (0xF6): LDVC(str path), TCOL(int), TCOT(str content)
   - GetPrivacyPolicyContent (0x2F): LDVC(str path), TCOL(int), TCOT(str content)

### What to test:
Run `.\frida_test.ps1` to see if:
- CreateAccount TDF decode now consumes bytes (was 0, should be >0)
- The handler advances the state machine to Login
- Game sends Login instead of Logout after CreateAccount

### If TDF decode still fails (0 bytes consumed):
The Frida v32 script traces the decoder execution with Stalker to identify exactly
which function fails. Compare the CA decoder call graph with the PreAuth decoder
call graph to find the difference.

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

## CURRENT BOTTLENECK — POST-CREATEACCOUNT STATE ADVANCE

The PreAuth trampoline (Patch 8 v3) works — the original PreAuth handler runs with param_3=0,
processes the decoded response, calls FUN_146e1e460 (Ping) and FUN_146e1c3f0 (Login processor).
The game now does everything on one connection: PreAuth → Ping → FetchClientConfig ×6 → CreateAccount → Logout.

The problem: after CreateAccount, the game sends Logout instead of Login. The CreateAccount
cave (Patch 16) just sets a flag and returns — it doesn't advance the state machine to Login.

The CreateAccount handler (FUN_146e151d0) needs to call the state transition to advance to Login.
But the handler object's vtable is too small for vtable+0xb8 (reads garbage), and param_1[1]
points to heap data, not the state machine.

### Key finding from Frida v31:
- handler.vtable+0xb8 = 0x485455415f525245 (ASCII "ERE_AUTH" — garbage, not a function)
- handler+0x08 = heap data, not state machine
- The state machine is at rpc+0x20 (vtable 0x14389f938) but not accessible from the handler

### Next steps:
1. Fix the TDF encoding so CreateAccount response is decoded properly (UID non-zero at +0x13)
   - This would let the ORIGINAL handler code run and call the state transition naturally
   - The PreAuth TDF decode works (325 bytes consumed), so the encoder is partially correct
   - CreateAccount TDF decode fails (0 bytes consumed) — need to investigate why
2. OR: Find a way to access the state machine from the handler object
3. OR: Go back to the OSDK account creation screen and make it functional

## FALLBACK PLAN — OSDK ACCOUNT CREATION SCREEN

If fixing TDF doesn't work, we can return to the OSDK account creation screen.

### How to trigger it:
In the CreateAccount cave (Patch 16), restore the old approach that set state bytes
via vtable+0xb8 and called the state transition (1, 3). Specifically:
1. Call vtable+0xb8 on param_1 (handler) to get state object
2. Set *(state + 0x8bc) = 0 (success)
3. Set *(state + 0x8c0) = 0x01 (UID non-zero)
4. Set *(state + 0x8c6) = 1 (persona creation flag — THIS triggers the screen)
5. Call (*(*(param_1[1]) + 8))(param_1[1], 1, 3) — state transition
   NOTE: This actually calls an EASTL assert (NOP), but the screen appears anyway
   because setting 0x8c6=1 is what triggers it.

### What the screen looks like:
- Title: *TXT_OSDK_ACCOUNT_CREATION (broken localization)
- Fields: Email, Password, *TXT_OSDK_REENTER_PASSWORD, *TXT_OSDK_CREATE_PERSONA
- Dropdowns: Country (Afghanistan default), DOB (Jan 01 2009 default)
- Radio buttons: data sharing, contact prefs, *TXT_OSDK_REMEMBER_PASSWORD
- Loading spinner ("17" icon) — fields NOT interactable

### What the game sends during the screen:
- cmd=0x00F2 (GetLegalDocsInfo): CTRY="", PTFM=4
- cmd=0x00F6 (GetTermsOfServiceContent): CPFT=4, CTRY="", FTCH=1, LANG="", TEXT=0
- cmd=0x002F (GetPrivacyPolicyContent): same fields
- Then Ping packets every ~3 seconds

### Why it's stuck:
The TOS responses ARE decoded (54-94 bytes consumed with actual text content).
But the screen stays in loading state. Possible causes:
- The TOS response TDF field names (LDVC, TCOL) might be wrong
- The game might need additional fields beyond LDVC and TCOL
- The OSDK UI might be waiting for a Nucleus HTTPS call that's failing silently
- The form fields might need the OSDK localization strings to be loaded

### To make it functional:
1. Use Frida to hook the TOS response handlers and see what fields they read
2. Find the correct TDF field names from Ghidra's response structure at PTR_DAT_1448787e0
3. Try returning the TOS content in different TDF structures (struct wrapper, etc.)
4. Check if the game makes HTTPS requests to port 443 during the screen

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
