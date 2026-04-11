# FIFA 17 FUT Private Server - Next Session Plan

## BREAKTHROUGH APPROACH: Hook ProtoSSL at the Application Layer

### The Problem (Solved Analysis)
We spent 50+ patches trying to bypass cert verification inside ProtoSSL's SSL state machine. The verification is too deeply integrated — skipping it also skips the public key extraction needed for the handshake.

### The Solution: Force Plaintext Mode
From reading the DirtySDK source code:

```c
int32_t ProtoSSLSend(ProtoSSLRefT *pState, const char *pBuffer, int32_t iLength) {
    if (pState->iState == ST3_SECURE) {
        // Encrypt and send via SSL
        _SendPacket(pState, SSL3_REC_APPLICATION, NULL, 0, pBuffer, iLength);
    }
    if (pState->iState == ST_UNSECURE) {
        // Send plaintext via raw socket!
        iResult = SocketSend(pState->pSock, pBuffer, iLength, 0);
    }
}
```

When `iState == ST_UNSECURE`, ProtoSSL sends/receives in **plaintext**. No SSL, no certs, no verification.

### Implementation Plan

**Option A: Frida hook on ProtoSSLConnect**
1. Find `ProtoSSLConnect` in FIFA 17 (search for the connect pattern)
2. After it connects, set `pState->iState = ST_UNSECURE` (offset +0x8C)
3. The game sends plaintext Blaze data to our server
4. Our server receives raw Blaze packets (no TLS needed!)

**Option B: Patch the SSL state machine to skip to ST_UNSECURE**
1. In the SSL state machine, after State 1 (ClientHello), instead of proceeding to State 2 (ServerHello), jump to ST_UNSECURE
2. This means: game connects, sends ClientHello, we respond, then game switches to plaintext

**Option C: Hook at the Winsock level (EA-MITM approach)**
1. Find ProtoSSLConnect, ProtoSSLSend, ProtoSSLRecv addresses in FIFA 17
2. Hook them to redirect to our server and intercept plaintext data
3. This is what EA-MITM does for BF3/NFS

### Key Addresses
- SSL state machine: exe+0x6126213
- iState offset in struct: +0x8C (confirmed from code: `CMP DWORD [rbx+0x8C], 3`)
- bAllowAnyCert offset: +0xC20 (confirmed from code: `CMP BYTE [rbx+0xC20], 0`)
- Error handler: exe+0x612E770
- Disconnect: exe+0x612D5D0
- "installed CA cert" string: exe+0x39316B1

### Server Changes Needed
If we force plaintext mode, the server needs to accept raw TCP Blaze packets instead of TLS. The main Blaze server on port 10041 already does this. We just need the redirector on port 42230 to also accept plaintext.

### What We Know Works
- NOP-ing the error CALL at exe+0x612644E prevents disconnect (HANGING result)
- The game's SSL state machine is at exe+0x6126213
- Frida can successfully patch code in the Denuvo-decrypted process
- The batch test framework works for rapid iteration
