# FIFA 17 SSL Bypass - STATUS

## ✅ COMPLETED: TLS Handshake (April 12, 2026)

The full TLS 1.2 handshake with the game is working:

1. DLL sets `bAllowAnyCert` at offset +0x384 (Ghidra-verified)
2. Game accepts our certificate, sends ClientKeyExchange
3. RSA decryption of pre-master secret succeeds (48 bytes, version 0x0303)
4. Master secret + key derivation via TLS 1.2 PRF (SHA-256) works
5. Client Finished verify_data: **MATCHES** (proves our PRF + key derivation is correct)
6. Client Finished MAC (HMAC-SHA1): **MATCHES** (proves our MAC keys are correct)
7. Server Finished computed with hash including client's Finished message
8. Game accepted server Finished — **no alert, no disconnect**
9. Game sent 858 bytes of encrypted application data — **decrypted successfully**

### Key Technical Details
- Cipher: TLS_RSA_WITH_RC4_128_SHA (0x0005)
- Version: TLS 1.2 (0x0303) in both record layer and handshake
- PRF: SHA-256 based (tls12PRF, not the MD5+SHA1 split from TLS 1.0)
- Finished: 12 bytes = PRF(master_secret, label, SHA256(all_handshake_messages))
- Critical fix: server Finished hash MUST include client's Finished message
- Record MAC: HMAC-SHA1 with sequence numbers

## CURRENT: Full Connection Flow

After the TLS handshake on the redirector (port 42230), the game:
1. Sends a Blaze GetServerInstance request (encrypted) — **working**
2. Expects a redirect response pointing to the main Blaze server
3. Connects to the main Blaze server (port 10041)
4. The main server connection may also need TLS (SECU flag controls this)

### What's needed:
- Verify the 858-byte decrypted data is parsed as a Blaze packet correctly
- Ensure the redirect response is sent back encrypted and the game processes it
- Handle the main Blaze server connection (plain TCP or TLS depending on SECU)
- The redirector currently sends SECU=0 (no security), so main server should be plain TCP
