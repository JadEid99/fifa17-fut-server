# FIFA 17 Private Server - SESSION END STATUS (April 12, 2026)

## DEFINITIVE FINDINGS
1. PreAuth response content DOES NOT MATTER (proven with real BF4 EA server response)
2. secure=0 vs secure=1 DOES NOT MATTER (game uses TLS regardless)
3. Origin auth function (146f19a11) is NEVER called (x64dbg confirmed)
4. Origin SDK check (1470e2840) is called CONSTANTLY (game polls it)
5. Game always: PreAuth → close_notify → disconnect. No Login ever sent.
6. Redirector stays open 30+ seconds but receives no more data
7. Main server stays open ~10 seconds then closes
8. No connections to any other ports

## ROOT CAUSE THEORY
The game needs a real Origin SDK session object (not just the availability check).
DAT_144b7c7a0 should point to an initialized Origin SDK object. Our patch makes
the null check pass, but the game then tries to call methods on the object and
fails because there's no real object.

The STP emulator (stp-origin_emu.dll) handles Denuvo licensing but doesn't
provide a full Origin SDK session. The game can't get an auth token without
a real Origin SDK session.

## APPROACH FOR NEXT SESSION
1. Find DAT_144b7c7a0 in Ghidra - see what initializes it
2. The Origin SDK init function (FUN_1470e2850) might need to be called/faked
3. Alternative: find where the game decides "I have an auth token, send Login"
   and force that code path
4. Alternative: hook the game's Blaze send function and inject a silentLogin
   packet directly from the DLL
5. Alternative: find a more complete Origin emulator that provides auth tokens

## ALL WORKING COMPONENTS
- DLL v55: cert bypass + Origin SDK check + auth flag bypass
- TLS 1.2 with RC4-SHA on both connections
- HTTP redirect over TLS
- Blaze PreAuth with correct TDF encoding (varint 0x80 continuation)
- Fire2 16-byte header format
- Hosts file redirects

## KEY FILES
- dll-proxy/dinput8_proxy.cpp (v55)
- server-standalone/server.mjs
- BF4BlazeEmulator/ (reference)
- stp-origin_emu.dll + .ini
