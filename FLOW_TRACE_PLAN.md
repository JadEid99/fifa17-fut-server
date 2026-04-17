# FIFA 17 — Forensic Trace Plan

## Goal
Stop guessing. Build a complete map of the game's decision-making from
"FetchClientConfig completes" to "Logout is sent." Identify the exact
function call and state value that decides Logout instead of Login.

## Method
Passive Frida instrumentation (no patches). Log every relevant function
entry/exit with register values and key memory state at each transition.

## Target Functions to Instrument

### Authentication / Login Chain
| Address | Name | What to log |
|---------|------|-------------|
| `0x146e1cf10` | PreAuth response handler | R8 (error code), return |
| `0x146e1c3f0` | Login types processor | loginSM+0x218/+0x220 count, +0x53f flag |
| `0x146e1dae0` | Login check (iterator) | array count, return value |
| `0x146e1eb70` | Login RPC sender | params, return (job handle) |
| `0x146e19720` | Login start | |
| `0x146e19b30` | Login fallback (no types) | Always triggers when types empty |

### Auth Code Path
| Address | Name | What to log |
|---------|------|-------------|
| `0x1470db3c0` | OriginRequestAuthCodeSync | Patched by DLL cave |
| `0x1470e67f0` | Origin SDK RequestAuthCode | param_2 (user ID), return |
| `0x1470e1ed0` | LSX SendXml+Wait | XML being sent, return |
| `0x1470e2840` | IsOriginSDKConnected | DAT_144b7c7a0 value |
| `0x146f199c0` | FirstPartyAuthTokenRequest | slot values, request object |

### Online State Machine
| Address | Name | What to log |
|---------|------|-------------|
| `0x146f30710` | Main online tick (HUGE) | Skip - too big |
| `0x146f33340` | connState check (+0x1c0) | Return value |
| `0x146f7c7e0` | Online tick entry | Called every frame |
| `0x147102800` | Origin Login event dispatcher | IsLoggedIn parsed |
| `0x147138640` | Login event parser | Attribute values |

### RPC Wire Send
| Address | Name | What to log |
|---------|------|-------------|
| `0x146df0e80` | RPC send (wire-level) | component, command, msgId |
| `0x146dab760` | RPC builder | component, command |
| `0x1478aa0f0` | Job creator | job handle, timeout |

## Key Memory Checkpoints to Dump

At three moments — end of PreAuth handler, end of last FetchClientConfig, and right before Logout RPC:

1. **OnlineManager** (`DAT_1448a3b20`):
   - +0x1c0 (connection state)
   - +0x1f0 (game mode state)
   - +0x13b8 (connState for UI)
   - +0x4e98..+0x4ed8 (auth request slots)
   - +0x4ece (auth fail flag)

2. **BlazeHub** (via OnlineMgr+0xb10 → +0xf8):
   - +0x53f (connection flag)

3. **loginSM** (`preAuthParam1 + 0x1DB0` or similar):
   - +0x218 / +0x220 (login type array start/end pointers)
   - +0x18 (job handle)
   - +0x53f flag

4. **Origin SDK object** (`DAT_144b7c7a0`):
   - !=0 check
   - +0x3a0 (user ID)
   - +0x35c (port)

## Output Format

For each hook event, emit one line:
```
[T+ms] [FUNC] rcx=... rdx=... r8=... r9=... ret=... notes
```

At checkpoints, emit multiple lines dumping all relevant fields.

## Sequence of Events We Need to Capture

1. DLL loaded, patches applied
2. Origin IPC challenge/response
3. Blaze TLS handshake on 42230
4. Redirector response
5. Blaze main connection on 10041
6. PreAuth sent
7. PreAuth response received → `FUN_146e1cf10` called
   - CHECKPOINT 1: dump all state
8. `FUN_146e1c3f0` called — does it execute the `+0x53f` branch?
9. Login types read from PreAuth TDF into `+0x218/+0x220`
10. `FUN_146e1dae0` called — does it return 0 or 1?
11. If 0: `FUN_146e19b30` called (fallback)
12. Ping, FetchClientConfig x 6
    - CHECKPOINT 2: dump state after last FetchClientConfig
13. Something decides: send Logout
    - CHECKPOINT 3: dump state + full call stack right before `FUN_146df0e80` with cmd=0x46
14. `FUN_146df0e80(comp=0x0001, cmd=0x0046)` — Logout sent

## Analysis After Capture

We compare CHECKPOINT 1 vs 2 vs 3. The deltas tell us:
- What changed between "PreAuth done" and "Logout decided"
- Which code path ran to decide Logout
- What state field triggered it

Then we know exactly what needs to be true for Login to be sent instead.
