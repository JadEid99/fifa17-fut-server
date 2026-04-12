# FIFA 17 Private Server - COMPREHENSIVE STATUS (April 12, 2026)

## WHAT WORKS PERFECTLY
- DLL v55: 3 code patches (cert bypass, Origin SDK, auth flag) - all apply in ~500ms
- TLS 1.2 handshake with RC4-SHA on both redirector (42230) and main server (10041)
- HTTP redirect over TLS on redirector (game gets server address)
- Blaze PreAuth parsed correctly over TLS on main server
- TDF encoding with correct varint (0x80 continuation bit)
- Game confirms our PreAuth is parsed ("servers shut down" message when hosts not redirected)

## THE UNSOLVED BLOCKER
Game sends PreAuth on main server, receives response, sends TLS close_notify, disconnects.
Never sends Login/SilentLogin. The Origin auth function (146f19a11) is NEVER called (confirmed by x64dbg).

## CONFIRMED FACTS (from x64dbg + connection monitor)
- Redirector connection stays open 30+ seconds but game sends NO more data on it
- Main server connection stays open ~10 seconds then closes
- STP emulator (port 4216) connection unchanged
- No connections to any other ports (443, 80, 8080, 9988, 17502)
- The Blaze command dispatcher (1461334d0) fires multiple times during connection
- The Origin auth request function (146f19a11) NEVER fires

## WHAT WE'VE TRIED (all same result - PreAuth then close)
- Empty response, no response, different body fields
- Different header formats (msgType at offset 4, 12, packed)
- CIDS as type 0x04 (List) and 0x07 (IntList)
- INST = "fifa17-2016", "fifa-2017-pc"
- nucleusConnect/nucleusProxy URLs (real EA, localhost:8080)
- CONF as string, as map with 3 entries, as map with 7 entries
- Origin SDK bypass (always return true)
- Auth flag bypass (set [RSI+0xe8]=1)
- Extra hosts file entries for EA domains
- Catch-all port listeners

## KEY ADDRESSES (for Ghidra/x64dbg)
- 146132444: bAllowAnyCert check (PATCHED: JNZ→JMP)
- 1461334d0: Blaze command dispatcher (fires during connection)
- 146f19a11: OriginRequestAuthCodeSync call (NEVER fires)
- 146f199c0: FirstPartyAuthTokenRequest function
- 1470db3c0: OriginRequestAuthCodeSync wrapper
- 1470e2840: Origin SDK availability check (PATCHED: always true)
- 1470e2850: Origin SDK initialize function

## NEXT APPROACH TO TRY
The game's Blaze client has a state machine. After PreAuth, it should transition
to a "login" state. Something in our PreAuth response (or missing from it) prevents
this transition. The most promising approach:

1. Use x64dbg to set a breakpoint on the Blaze state machine transition function
   and trace what state the client is in after PreAuth
2. Find the function that decides whether to proceed to login after PreAuth
3. Compare our PreAuth response byte-for-byte with the BF4 emulator's hardcoded
   response (which is a captured real server response)
4. The BF4 emulator has 3 different hardcoded PreAuth responses - try using one
   of them directly (adapted for FIFA 17) to see if the format matters

## FILES
- dll-proxy/dinput8_proxy.cpp (v55 - 3 patches)
- server-standalone/server.mjs (TLS + Blaze server)
- batch_test.ps1, monitor_connections.ps1 (testing)
- BF4BlazeEmulator/ (reference implementation)
- stp-origin_emu.ini (PersonaId=33068179, PersonaName=Player)
