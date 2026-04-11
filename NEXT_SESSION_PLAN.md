# FIFA 17 FUT Private Server - Next Session Plan

## What We've Built
- Node.js Blaze protocol server (redirector + main server + HTTP API)
- Manual TLS handshake implementation
- dinput8.dll proxy DLL that patches game memory at runtime
- Rust SSL proxy using blaze-ssl-async
- Frida scripts for runtime analysis

## The SSL Problem (Solved Analysis, Unsolved Implementation)
FIFA 17's ProtoSSL (DirtySDK v15.1.2.1.0) has a hardcoded CA certificate.
Our server cert isn't signed by this CA, so the cert PARSING function rejects it.
We can't skip the parsing because it extracts the RSA public key needed for ClientKeyExchange.

## Fresh Approach: Hook SetCACert to Replace the CA

The game calls `_ProtoSSLSetCACert` to load its CA certificate at startup.
We saw the string: `[0x%p]DirtySdkHttpProtoImpl::SetCACert(%p, %d) - installed CA cert.`

**Plan:**
1. In our dinput8.dll, hook the function that calls SetCACert
2. When it's called, capture the CA cert data (the `%p` and `%d` parameters = pointer and size)
3. Replace it with OUR CA cert data
4. Now ProtoSSL will use our CA to verify certs, and our server cert will pass

This is the cleanest approach because:
- We don't need to patch any verification code
- We don't need to understand the cert parsing internals
- The game's own verification code runs normally — it just uses our CA instead of EA's
- All the crypto (RSA key exchange, RC4/AES encryption) works correctly

**Implementation:**
- Search for the `SetCACert` string reference in memory
- Find the function that passes the cert data
- Replace the cert data buffer with our CA cert (DER format)
- Our CA cert is 804 bytes (already generated)

## Alternative Approach: Intercept at Winsock Level

Instead of fighting ProtoSSL, intercept ALL network I/O:
1. Hook `send()` and `recv()` in WS2_32.dll
2. When the game sends a ClientHello, handle the TLS handshake ourselves
3. Forward decrypted Blaze packets to our Node.js server
4. Encrypt responses and feed them back to the game

This is essentially a local TLS proxy inside the game process.
More complex but completely bypasses ProtoSSL.

## Key Addresses (Runtime, After Denuvo Decryption)
- SSL state machine: +0x6126213 to +0x6128033
- State 1 (ClientHello): +0x6126213
- State 2 (ServerHello): +0x61262A9
- State 3 (Certificate): +0x61262DC
- State 4 (ServerHelloDone): +0x612634D
- State 5 (ClientKeyExchange): +0x6126416
- State 6 (ChangeCipherSpec): +0x6126463
- State 7 (Finished): +0x6126439
- Error handler: +0x612E7A4
- Disconnect function: +0x612D5D0
- Cert receive: +0x6127B40
- Cert process: +0x6127020
- Cert verify: +0x6124140
- Cert finalize: +0x61279F0

## Files on Jad's PC
- `C:\Users\Jad\fifa17-server\server.mjs` - Node.js server
- `C:\Users\Jad\fifa17-server\dll-proxy\` - DLL proxy project
- `C:\Users\Jad\fifa17-server\ssl-proxy\` - Rust SSL proxy
- `D:\Games\FIFA 17\dinput8.dll` - Current DLL proxy (installed)
- `D:\Games\FIFA 17\fifa17_ssl_bypass.log` - DLL log output
- Hosts file: `127.0.0.1 winter15.gosredirector.ea.com`
- CA cert installed in Windows trust store

## Tools Installed
- Node.js v20, Rust 1.94, MSVC Build Tools 2022, Frida 17.9.1, mitmproxy
