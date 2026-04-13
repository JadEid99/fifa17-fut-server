# FIFA 17 Private Server — Session Plan (End of Day 4)

## MAJOR PROGRESS TODAY

1. **DLL v97/v98 patch bypasses PreAuth response parsing** — calls `FUN_146e1e460` directly
2. **Game now sends Ping after PreAuth** — first time ever getting past PreAuth!
3. **Auto-logging works** — server auto-pushes results on disconnect
4. **Header format partially decoded** — 16-byte Fire2 header with 4-byte length prefix

## Current Pipeline Status

```
1. DNS Redirect          ✅ DONE
2. Redirector TLS        ✅ DONE  
3. GetServerInstance     ✅ DONE
4. Main Server TLS      ✅ DONE
5. PreAuth Request       ✅ DONE
6. PreAuth Response      ⚠️  SENT (game receives but RPC framework times out)
7. DLL bypass post-PreAuth ✅ DONE (v97 cave calls FUN_146e1e460)
8. Ping keepalive        ✅ DONE (game sends Ping, we respond)
9. Login setup           ❌ BLOCKED — FUN_146e1c3f0 never called
10. Login/SilentLogin    ❌ BLOCKED
11. PostAuth             ❌ BLOCKED
12. FUT Menu Access      ❌ BLOCKED
```

## What We Know About the Header (bytes 12-15)

From raw packet captures (plaintext main server):
```
PreAuth requests:  seq=02, 05, 08, 0B, 0E, 11 (incrementing by 3 per connection)
Null/error:        seq=03, 06, 09, 0C, 0F, 12 (always request+1)
Ping requests:     seq=04, 07, 0A, 0D, 10, 13 (always request+2)
```

Byte 12 is a GLOBAL sequence counter (increments across connections).
Byte 13: 0x00 = normal, 0x80 = error flag.
Bytes 14-15: always 0x0000.

## Two Parallel Problems

### Problem A: PreAuth Response Not Parsed by RPC Framework
The game's Blaze RPC framework returns ERR_TIMEOUT (0x40050000) for our PreAuth response.
This means the response header format is wrong — the framework can't match it to the pending request.

**Possible causes:**
- Wrong message type encoding at byte 12 (we echo seq, maybe need type+seq)
- Wrong byte 13 value for responses
- The 4-byte length prefix confuses the parser
- TDF body format mismatch (BF4 response vs FIFA 17 expected format)

**What to try next:**
1. Use Frida to hook the raw packet receive function and see what the game reads
2. Try sending response with BlazePK-rs 12-byte format (no 4-byte prefix)
3. Try different byte 12 values: 0x10|seq, seq+1, same seq
4. Build a proper FIFA 17 PreAuth response TDF (not BF4 captured data)

### Problem B: Login Flow Not Triggered
Even with the DLL bypass, `FUN_146e1c3f0` (login type processor) is never called.
Our cave only calls `FUN_146e1e460` which sends a Ping, not Login.

**What FUN_146e1c3f0 needs:**
- `param_1 + 0x3b6`: login state machine object (part of the Blaze hub)
- `param_2 + 0x120`: login types list from PreAuth response TDF
- `param_3`: callback pointer
- `param_4`: some config value

**What to try next:**
1. Populate the login types list in memory manually from the DLL
2. Call FUN_146e1eb70 directly with a fake login type entry
3. Call FUN_146f2a270 (Login sender) directly
4. Fix Problem A so the natural flow works

## Key Ghidra Findings

### FUN_146e1cf10 (PreAuth response handler) — PATCHED by DLL v97
- param_3 == 0: Extract config → call FUN_146e1e460 → call FUN_146e1c3f0
- param_3 != 0: Schedule error callback → disconnect

### FUN_146e1e460 (post_PreAuth) — Called by our DLL cave
- Sends Ping RPC (comp=9, cmd=2) — NOT PostAuth as we assumed
- Also registers a QoS callback

### FUN_146e1c3f0 (login type processor) — NOT called yet
- Reads login types from PreAuth response
- Checks BlazeHub+0x53f flag (we force to 1)
- Calls FUN_146e1dae0 which iterates login types
- Each login type calls FUN_146e1eb70 to initiate login

### FUN_146e19a00 (PreAuth completion) — Partially NOPed
- Disconnect call NOPed ✅
- Cleanup call NOT NOPed (scan range too small, need 150+ bytes)
- Still schedules callback via FUN_146da9570

## Recommended Approach for Next Session

**Option 1 (Fix the response format):**
Use Frida to hook the Blaze frame parser inside the game. See exactly what bytes
the game reads and where it fails. This would definitively tell us the correct
header format. Then fix the server response.

**Option 2 (Bypass everything from DLL):**
Expand the DLL cave to also call FUN_146e1c3f0 with fake login type data.
This requires understanding the login type data structure (0x20 bytes per entry)
and populating it correctly. Complex but doesn't depend on fixing the server.

**Option 3 (Hybrid):**
Fix the cleanup NOP (increase scan range to 150 bytes) so the connection stays
alive longer. Then use Frida to trace what happens after the Ping — maybe the
game IS trying to do more but the cleanup kills the connection.

**Recommendation: Option 3 first (quick fix), then Option 1 (definitive answer).**
