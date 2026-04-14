# FIFA 17 Private Server — Day 4 Progress Report

## Pipeline Status

```
 1. DNS Redirect          ✅ DONE
 2. Redirector TLS        ✅ DONE
 3. GetServerInstance     ✅ DONE
 4. Main Server Connect   ✅ DONE (plaintext, secure=0)
 5. PreAuth               ✅ SOLVED (byte13=0x20 response format)
 6. FetchClientConfig     ✅ DONE (6 OSDK configs served)
 7. Origin Online Check   ✅ BYPASSED (DLL v100: patch FUN_1470e0390)
 8. Version Check         ✅ BYPASSED (DLL v101: patch FUN_1470da720 + FUN_145e280b0)
 9. CreateAccount         ❌ CURRENT — game sends comp=0x0001 cmd=0x000A
10. Login/SilentLogin     ❌ NEXT
11. PostAuth              ❌ BLOCKED
12. FUT Menu Access       ❌ BLOCKED
```

## Key Discoveries

### Blaze Header Format (CONFIRMED)
```
[0-3]   u32  payload length
[4-5]   u16  secondary length (always 0)
[6-7]   u16  component
[8-9]   u16  command
[10-11] u16  error code
[12]    u8   sequence number (global counter)
[13]    u8   type/flags
[14-15] u16  reserved (always 0)
```

Response format: byte12 = echo request's seq, byte13 = 0x20

### DLL Patches Applied (v101)
1. Cert verification bypass (JNZ→JMP)
2. Origin SDK availability (always true)
3. FUN_1470db3c0 body replacement (fake auth code)
4. Auth bypass flag
5. IsLoggedIntoEA (always true)
6. IsLoggedIntoNetwork (always true)
7. SDK gate (always return 1) + login vtable checks
8. FUN_146e1cf10 (PreAuth response handler) → call post_PreAuth directly
9. FUN_146e19a00 (PreAuth completion) → immediate RET
10. FUN_1470e0390 (OriginCheckOnline) → always online
11. FUN_1470da720 (GetGameVersion) → return 0
12. FUN_145e280b0 (version compare) → always match

### OSDK Configs Served
- OSDK_CORE: connIdleTimeout, defaultRequestTimeout, pingPeriod, etc.
- OSDK_CLIENT: clientVersion, minimumClientVersion, updateUrl, forceUpdate
- OSDK_NUCLEUS: nucleusConnect, nucleusProxy, nucleusPortal
- OSDK_WEBOFFER: offerUrl
- OSDK_ABUSE_REPORTING: enabled=0
- OSDK_XMS_ABUSE_REPORTING: enabled=0

### Game Sends CreateAccount (comp=0x0001 cmd=0x000A)
- 38 bytes of TDF body
- Sent after all OSDK configs are loaded
- Game expects account creation response with player ID, session key, etc.
- SVCN = "fifa-2017-pc-trial" (FitGirl repack detected as trial)
