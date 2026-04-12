# FIFA 17 Private Server - STATUS (April 12, 2026)

## ✅ COMPLETED
- DLL v52: Permanent code patch (JNZ→JMP at 0x14613244B) - 156ms at startup
- Redirector: TLS + HTTP redirect (secure=1) on port 42230
- Main server: TLS handshake on port 10041
- Blaze PreAuth: parsed and responded (MAC-verified close_notify confirms crypto is correct)
- Fire2 16-byte header, TDF varint encoder fixed
- STP Origin emulator on port 4216 is working (game communicates with it)
- Hosts file: all EA hostnames redirected to 127.0.0.1

## CURRENT BLOCKER: Game sends close_notify after PreAuth response
- close_notify MAC verified correct — game intentionally closes after PreAuth
- No connections to any other ports after PreAuth
- PreAuth response is 328 bytes with proper TDF encoding

## NEXT SESSION PRIORITIES
1. Decode the game's 203-byte PreAuth REQUEST body to see what fields it sends
2. Compare our PreAuth response structure with real EA server responses
3. Check if the response needs the LTPS map populated (currently empty struct)
4. Try sending the response as HTTP-wrapped (like redirector) instead of raw Blaze
5. Check if the game expects the main server to also use HTTP protocol (like redirector)
6. The game might expect the Blaze connection to use HTTP framing on port 10041 too

## KEY INSIGHT FROM NETSTAT
- Port 4216: STP Origin emulator (always connected, working)
- Port 42230: Redirector TLS (working)
- Port 10041: Main server TLS (connects, PreAuth, close_notify)
- No other ports attempted

## FILES
- dll-proxy/dinput8_proxy.cpp (v52)
- server-standalone/server.mjs
- batch_test.ps1
- stp-origin_emu.ini (PersonaId=33068179, PersonaName=Player)
