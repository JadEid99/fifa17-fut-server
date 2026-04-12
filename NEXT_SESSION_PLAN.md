# FIFA 17 Private Server - STATUS (April 12, 2026)

## ✅ COMPLETED: Full TLS on Both Connections
- DLL v52: Permanent code patch (JNZ→JMP) bypasses cert verification for ALL SSL connections
- Redirector TLS handshake: working
- Main server TLS handshake: working (with secure=1 in redirect)
- HTTP redirect over TLS: working
- Blaze PreAuth over TLS on main server: parsed and responded

## CURRENT: Game disconnects after PreAuth response
- Game connects to main server over TLS
- Sends PreAuth (comp=0x0009, cmd=0x0007) — 219 bytes
- We respond with 228 bytes (PreAuth response with CIDS, CONF, QOSS, etc.)
- Game sends close_notify (graceful TLS close) and disconnects
- Game does NOT reconnect for PostAuth/Login

### Possible causes:
1. PreAuth response body is wrong/incomplete — game doesn't like our TDF content
2. Game expects to send multiple packets on same connection (PreAuth + Login)
3. Game reconnects but to a different port/host based on PreAuth response content
