# FIFA 17 SSL Bypass - CURRENT STATUS

## BREAKTHROUGH ACHIEVED
- DLL sets bAllowAnyCert at offset +0x384 (found via Ghidra)
- Game accepts our certificate and sends ClientKeyExchange
- RSA decryption works, master secret derived
- Game sends ChangeCipherSpec + encrypted Finished

## CURRENT BLOCKER: Server Finished Message
The game rejects our server's Finished message (sends encrypted alert).

### Root Cause (from Ghidra analysis of FUN_146131560):
The server's Finished verify_data must include the CLIENT's Finished message
in the handshake hash. Our server computes the hash BEFORE receiving the
client's Finished, so the hash is incomplete.

### Fix Required:
1. Receive client's ChangeCipherSpec
2. Initialize RC4 decryption with clientWriteKey
3. Decrypt client's Finished message
4. Add client's Finished to the handshake hash
5. THEN compute server's Finished: PRF_SHA256(master, "server finished", SHA256(all_messages))
6. Encrypt and send server's ChangeCipherSpec + Finished

### Crypto Details (from Ghidra):
- Version: TLS 1.2 (0x0303)
- PRF: SHA-256 based (FUN_146131a60)
- Finished: 12 bytes = PRF(master_secret, "server finished", SHA256(all_handshake_messages))
- Record MAC: HMAC-SHA1 (cipher suite RC4-SHA)
- The handshake hash includes ALL messages including client's Finished
