# FIFA 17 Private Server — PreAuth SOLVED (Day 4)

## How We Got Past PreAuth

### The Problem (stuck for 3+ days)
The game sent PreAuth, we responded, but the game's RPC framework returned ERR_TIMEOUT (0x40050000) and disconnected. Our response was never processed.

### Root Cause
The Blaze packet header format was wrong. FIFA 17 uses a 16-byte Fire2 header:

```
[0-3]   u32  payload length
[4-5]   u16  secondary length (always 0)
[6-7]   u16  component
[8-9]   u16  command
[10-11] u16  error code
[12]    u8   sequence number (global counter, increments per packet)
[13]    u8   type/flags
[14-15] u16  reserved (always 0)
```

### The Fix (two parts)

**Part 1: DLL v99 patch** — Replace FUN_146e19a00 (PreAuth completion handler) with RET.
This prevents the game from disconnecting after the RPC timeout. Without this, the game
tears down the connection before our response can be processed.

**Part 2: Response header byte 13 = 0x20** — The response type flag.
- `0x00` = request (game ignores our response)
- `0x10` = response type (game ignores)
- `0x20` = notify type (GAME PROCESSES IT!) ← THIS WORKS
- `0x80` = error flag (game reads but rejects with 0xA0)

Byte 12 must echo the request's sequence number.

### Confirmed Result
Game shows: "Unable to connect to the EA servers. In order to access the online
features of this title you must first log in to Origin in Online Mode."

This means the game successfully processed PreAuth, extracted server config, and
attempted to authenticate — but failed because there's no Origin session.

### Packets the game sends after PreAuth
1. 6x FetchClientConfig (comp=0x0009, cmd=0x0001) — asks for OSDK_CORE etc.
2. 1x Auth request (comp=0x0001, cmd=0x0046)

## Current Pipeline Status

```
1. DNS Redirect          ✅ DONE
2. Redirector TLS        ✅ DONE
3. GetServerInstance     ✅ DONE
4. Main Server TLS      ✅ DONE
5. PreAuth               ✅ SOLVED!
6. FetchClientConfig     ❌ NEXT — need proper config responses
7. Login/Auth            ❌ NEXT — need to handle cmd=0x0046
8. PostAuth              ❌ BLOCKED
9. FUT Menu Access       ❌ BLOCKED
```
