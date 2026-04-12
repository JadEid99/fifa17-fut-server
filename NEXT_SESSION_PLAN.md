# FIFA 17 Private Server - STATUS (April 12, 2026)

## ✅ COMPLETED
- DLL v52: Permanent code patch (JNZ→JMP at 0x14613244B) bypasses cert verification
- Redirector: TLS handshake + HTTP redirect (secure=1) on port 42230
- Main server: TLS handshake on port 10041
- Blaze PreAuth: parsed (comp=0x0009 cmd=0x0007) and responded over TLS
- Fire2 16-byte header format confirmed and working
- TDF varint encoder fixed (continuation bit 0x80 for bytes 1+)
- Hosts file: redirects EA hostnames to 127.0.0.1

## CURRENT BLOCKER: Game disconnects after PreAuth
- Game: TLS → PreAuth → close_notify → no further connections
- Tested: empty body, no response, different headers, different fields, extra hosts — all same
- No connections to ports 443, 80, 9988, 17502, 9946
- close_notify is graceful (level=1 desc=0), game closes TCP after

## THEORIES TO INVESTIGATE
1. Origin auth: STP emulator (stp-origin_emu.dll) might need config changes
   - Current: PersonaId=33068179, PersonaName=Player
   - Game might try Origin auth locally and fail before sending Login to Blaze
2. PreAuth response TDF body might have encoding issues beyond varint
   - Need to verify full 328-byte response (only 256 shown in hex dump)
   - LTPS struct, SVID, RSRC, SVER fields need verification
3. Game might expect specific CONF map keys or CIDS values for FIFA 17
4. The Blaze connection might need to be HTTP-wrapped (like redirector) not raw binary
5. Game might need a server-initiated notification before it sends Login

## KEY FILES
- dll-proxy/dinput8_proxy.cpp (v52 - permanent code patch)
- server-standalone/server.mjs (TLS + Blaze server)
- batch_test.ps1 (automated testing)
- stp-origin_emu.ini (Origin emulator config)
