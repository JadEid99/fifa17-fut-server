# FIFA 17 Online Connection Flow — Reverse Engineering Documentation

## Overview

This document maps the game's online connection flow from Ghidra decompilation.
All addresses are from the memory dump loaded at base `0x140000000`.

## Key Global Variables

| Address | Name | Type | Description |
|---------|------|------|-------------|
| `0x1448a3ac3` | Online Mode Flag | byte | Set to 1 during init. Gates ALL online functionality. |
| `0x1448a3b20` | OnlineManager Ptr | ptr | Main online state object. Created by `FUN_146f34270`. |
| `0x144b7c7a0` | Origin SDK Object | ptr | STP emulator's Origin SDK object. Checked by `FUN_1470e2840`. |
| `0x1448a20b8` | Memory Allocator | ptr | Used for allocating auth token buffers. |
| `0x144860ba0` | Frame Counter | uint32 | Incremented every frame, passed to `FUN_146f7c7e0`. |

## OnlineManager Object Layout (at `DAT_1448a3b20`)

| Offset | Type | Description |
|--------|------|-------------|
| `+0x7c` | int | Unknown state flag |
| `+0x98` | byte | Pending state change flag |
| `+0xb10` | ptr | Blaze connection manager object |
| `+0x13a0` | int | Last disconnect reason (for UI) |
| `+0x13a8` | byte | "Is disconnecting" flag (1 = disconnect in progress) |
| `+0x13ac` | int | Disconnect event fired flag |
| `+0x13b0` | int | Disconnect reason code |
| `+0x13b4` | uint16 | Disconnect status flags (0x101 = disconnect flagged) |
| `+0x13b8` | int | **Connection state** (0=idle, 1=disconnected-reason1, 2=disconnected-reason2) |
| `+0x13bc` | int | Disconnect sub-reason |
| `+0x1f0` | int | Game mode state (switch cases: 0,10,15,16,20,28,29,79,80,81,82,86,88) |
| `+0x2b10` | ptr | Event queue object |
| `+0x3058` | ptr | Network state object |
| `+0x3078` | ptr | Another network object (checked by `FUN_146f37500`) |
| `+0x4e98` | uint32 | Auth request type marker (0x682e) |
| `+0x4ea0` | ptr | **Auth token request slot 1** (one-shot, cleared after use) |
| `+0x4ea8` | ptr | **Auth token request slot 2** (usually NULL) |
| `+0x4eb0` | - | Auth request extended data |
| `+0x4ece` | byte | Auth-related flag (cleared on disconnect) |
| `+0x4ed0` | int | Used in reconnect logic |
| `+0x4ed8` | - | Mutex for auth operations |


## Function Map

### Game Loop
```
Main Game Loop (every frame)
  └─ FUN_146f7c7e0(frameCounter)          "Online tick"
       Gate: DAT_1448a3ac3 != 0 AND DAT_1448a3b20 != 0
       │
       ├─ Check +0x13b4 flag → handle disconnect UI
       ├─ Check +0x3058 → process network events
       ├─ Check +0x3078 → FUN_146f37500 → process pending ops
       ├─ Call Blaze connection update via +0xb10 vtable
       ├─ FUN_146f30710(onlineMgr)         "Main online state machine" (HUGE function)
       ├─ Check +0x98 → handle state changes
       ├─ Process event queue at +0x2b10
       └─ FUN_146f199c0(onlineMgr+0x4e98)  "Process auth token requests"
```

### Initialization
```
Game Startup
  └─ FUN_146f34270(param1, param2, param3)  "Initialize OnlineManager"
       ├─ Allocates 0x4f08 bytes for OnlineManager
       ├─ Calls FUN_146ef30b0 (constructor)
       │    ├─ Sets up vtables at offsets 0-8
       │    ├─ Initializes all state fields to defaults
       │    └─ Creates sub-objects (Blaze connection, auth, etc.)
       ├─ Stores result in DAT_1448a3b20
       └─ Sets DAT_1448a3ac3 = 1 (online mode active)
```

### Auth Token Flow
```
FUN_146f199c0(authArrayBase)              "Process first-party auth token requests"
  │  Iterates 2 slots at [base+8] and [base+16]
  │  For each non-NULL slot:
  │
  ├─ FUN_1470da6d0()                       "Get default Origin user"
  │    ├─ Checks FUN_1470e2840() → DAT_144b7c7a0 != 0  [PATCHED: always true]
  │    └─ Returns *(FUN_1470e3560() + 0x3a0) = *(DAT_144b7c7a0 + 0x3a0)
  │
  ├─ FUN_1470db3c0(user, reqObj+0x18, &authPtr, &authLen, 0)  [PATCHED: code cave]
  │    │  "OriginRequestAuthCodeSync"
  │    ├─ Checks FUN_1470e2840() → Origin SDK available?  [PATCHED: always true]
  │    ├─ Gets SDK object: FUN_1470e3560() → DAT_144b7c7a0
  │    └─ Calls FUN_1470e67f0(sdk, user, clientId, scope, &outPtr, &outLen)
  │         │  "Origin::OriginSDK::RequestAuthCode"
  │         │  This is the REAL auth code request that talks to STP via LSX socket
  │         ├─ Creates request object (0x1e8 bytes)
  │         ├─ Copies clientId and scope strings
  │         ├─ Calls FUN_1470e1ed0(req, 15000) → sends to STP, waits 15s timeout
  │         ├─ On success: copies auth code to output, returns 0
  │         └─ On failure: returns error code
  │
  ├─ If return == 0 AND authPtr != 0 AND authLen != 0:
  │    ├─ Allocates buffer: allocator(authLen+1)
  │    ├─ Stores at [reqObj + 0xd8] (auth token pointer)
  │    ├─ Copies auth code: FUN_145e27a50(buffer, authPtr, authLen)
  │    └─ Sets [reqObj + 0xe8] = 1 (auth ready flag)
  │
  ├─ If return != 0:
  │    └─ Logs "Origin Error %d" via FUN_146f6a240
  │
  └─ Clears slot: *slotPtr = 0 (one-shot, never retried)
```

### Origin SDK Layer
```
DAT_144b7c7a0                              "Origin SDK object pointer"
  │  Set by STP emulator DLL during game startup
  │  NULL if STP not loaded
  │
  ├─ FUN_1470e2840()                       "Is Origin SDK available?"
  │    Returns DAT_144b7c7a0 != 0          [PATCHED: always returns true]
  │
  ├─ FUN_1470e3560()                       "Get Origin SDK object"
  │    Returns DAT_144b7c7a0               (the raw pointer)
  │
  └─ Object layout:
       +0x70  → Inner object (vtable-based)
                +0x00 → vtable pointer
                         +0xd8 → IsLoggedIntoNetwork()  [PATCHED: always true]
                         +0xe0 → IsLoggedIntoEA()       [PATCHED: always true]
                         +0x100 → IsLoginInProgress()
       +0x3a0 → Default user ID
       +0x3b0 → Client ID string object
```

### Login Adaptor (registered callbacks)
```
FUN_147296980                              "Register all LoginAdaptor callbacks"
  ├─ StartLogin         → LAB_1472da2e0    (triggers full login UI)
  ├─ CancelLogin        → FUN_1472c03e0
  ├─ StartSilentLogin   → LAB_1472da330    (triggers background login)  
  ├─ CancelSilentLogin  → LAB_1472c05c0
  ├─ StartBootLogin     → LAB_1472caf50    (triggers boot-time login)
  ├─ IsLoggedIntoNetwork→ FUN_1472c68b0 → LAB_1472d4400 (vtable+0xd8)  [PATCHED]
  ├─ IsLoggedIntoEA     → LAB_1472c6870 → FUN_1472d43c0 (vtable+0xe0)  [PATCHED]
  ├─ IsLoginInProgress  → LAB_1472c6900 → LAB_1472d4440 (vtable+0x100)
  ├─ GetLoginInfo       → LAB_1472c3240
  ├─ GetNucleusAccountInfo → LAB_1472c3ab0
  └─ Logout             → FUN_1472c80b0
```

### Disconnect Flow
```
FUN_146f1f3b0(onlineMgr, reason, param3)   "Initiate disconnect"
  ├─ Sets +0x13a8 = 1 (disconnecting)
  ├─ Sets +0x13b0 = reason
  ├─ Clears +0x4ece (auth flag)
  ├─ Sets DAT_1448a3ac1 = 0
  ├─ Calls FUN_146f08cb0 (Blaze disconnect)
  └─ Complex state machine for cleanup

FUN_146f39a10(onlineMgr, reason, param3)   "Handle disconnect result"
  ├─ If reason == 0: calls FUN_146f1f3b0 (clean disconnect)
  ├─ If reason 1-15: 
  │    ├─ FUN_146f6c440 (log disconnect)
  │    ├─ Sets +0x13b8 = reason (CONNECTION STATE)
  │    ├─ Sets +0x13bc = sub-reason
  │    └─ Sets +0x13b4 = 0x101 (flagged)
  └─ Triggers FifaOnline::Disconnected event
```

## Connection State Machine

```
State 0 (Idle/Ready)
  │
  ├─ Game tick checks conditions → initiates Blaze connection
  │    └─ Redirector → PreAuth → gets server config
  │
  ├─ After PreAuth response received:
  │    └─ Game sends close_notify → disconnects
  │       (This is INTENTIONAL - PreAuth is a separate connection)
  │
  ├─ Game should then check auth token availability
  │    └─ If auth token ready → reconnect with Login request
  │    └─ If no auth token → stay disconnected (state 2)
  │
State 1 (Disconnected - retryable)
  │
State 2 (Disconnected - auth failed / non-retryable)
  │  ← THIS IS WHERE WE'RE STUCK
  │  The game sets state=2 because auth token is not available
```

## What We've Patched

| # | Target | What | Effect |
|---|--------|------|--------|
| 1 | `0x14613244B` | Cert verification JNZ→JMP | All TLS connections succeed |
| 2 | `FUN_1470e2840` | Origin SDK check | Always returns true |
| 3 | `0x146f19a11` | OriginRequestAuthCodeSync call | Code cave returns fake auth code |
| 4 | `0x1473ce785` | Telemetry auth flag | Always set to 1 |
| 5 | `FUN_1472d43c0` | IsLoggedIntoEA | Always returns true |
| 6 | `FUN_1472d4400` | IsLoggedIntoNetwork | Always returns true |

## Current Blocker

The auth token request (Patch 3) fires during game startup as a one-shot.
Our code cave replaces the CALL to `FUN_1470db3c0`, but we need to verify
whether the cave is actually being executed (v66 adds a marker for this).

If the cave IS executed: the fake auth code is provided but something
downstream rejects it or doesn't use it properly.

If the cave is NOT executed: the auth request fires before our patch is
applied (~600ms), goes through the real `FUN_1470db3c0` → `FUN_1470e67f0`
→ STP emulator → STP returns error → slot cleared → never retried.

## Key Insight from FUN_1470e67f0

The real auth code request (`FUN_1470e67f0`) sends a request to the STP
emulator via the LSX socket and waits up to **15 seconds** for a response:
```c
cVar1 = FUN_1470e1ed0(plVar5, 15000);  // 15000ms timeout
```
If STP doesn't respond with an auth code (it doesn't handle this), the
request times out and returns an error.
