# FIFA 17 Server Endpoint Analysis

## Critical Server Endpoints (Production)

### 1. Blaze Redirector (Game Server Discovery)
- `winter15.gosredirector.ea.com:42230` — Primary Blaze redirector
- `winter15.gosredirector.scert.ea.com` — Secure variant
- `spring18.gosredirector.ea.com` — Alternate redirector
- `gosca.ea.com:44325/redirector` — HTTPS redirector

The Blaze redirector is the first thing the game contacts. It tells the client which actual game server to connect to. This is the entry point for all online services.

### 2. Authentication / Nucleus
- `https://accounts.ea.com/` — EA Account authentication
- `https://signin.ea.com/` — EA Sign-in service
- `https://gateway.ea.com/` — EA Gateway (API proxy/router)

Internal/dev variants (not needed for production):
- `https://accounts.int.ea.com/`
- `https://signin.int.ea.com/`
- `https://gateway.int.ea.com/`

### 3. FUT / EASW (EA Sports World) API
- `content.lt.easfc.ea.com:8080` — EASFC content server
- `https://fifa17.service.easports.com/xmshd_collector/v1/` — Telemetry/data collector
- `https://fifa17.service.easports.com/xmshd_collector/v1/file/doupload.json` — File upload endpoint
- `http://89.234.41.144:8080/onlineAssets/2012/fut` — FUT online assets (hardcoded IP!)
- `%s/gameface/gameface_recipe?nucleus_id=%llu&sku_id=%s` — GameFace avatar API

### 4. Other EA Services
- `http://eastore.ea.com` — EA Store
- `http://fifa.easports.com` — FIFA website
- `http://support.ea.com` — EA Support
- `http://tos.ea.com` — Terms of Service
- `http://www.ea.com/%s/profile/forgot` — Password reset
- `demangler.ea.com` — Name demangling service
- `gosca.ea.com` — GOS Certificate Authority

## Key HTTP Headers (EASW Protocol)

These headers are used in FUT API requests:
- `EASW-Session:` — Session token
- `EASW-Token:` — Auth token  
- `EASW-Token:` — (duplicate reference, likely request + response)
- `EASW-Nucleus-Persona:` — Player persona identifier
- `EASW-Request-Signature:` — Request signing/integrity
- `Easw-Session-Data-Nucleus-Id: %lld` — Nucleus ID in session
- `EASW-Userid:` — User ID
- `EASW-Version: 2.0.5.0` — API version

## Authentication Flow (from memory strings)

1. Game starts → contacts `winter15.gosredirector.ea.com:42230` (Blaze redirector)
2. Redirector returns actual Blaze server address
3. Game authenticates via Blaze using EA/Origin credentials
4. Blaze returns Nucleus auth tokens
5. Game uses tokens to call EASW/FUT APIs with headers above
6. FUT flow: `startFutBlazeLogin` → `futBlazeLogin` → `postFUTBlazeLogin` → `CheckFUTRosters` → `futFlow`

## FUT Game Flow (Navigation)

From the nav flow strings:
```
OriginIsOnlineTrue → startFutBlazeLogin → startLoginWithoutMultiplayerCheck
loginSuccess → CheckFUTRosters
LaunchFUT → preLaunchFUTFlow → launchFUTFlow → futFlow
```

Key flow files:
- `/checkFUTRostersFlow.nav`
- `/fut/futFlow.nav`

## API URL Patterns

The `%s` format strings suggest the base URL is configurable:
- `%s/gameface/gameface_recipe?nucleus_id=%llu&sku_id=%s`
- `&nucleusId=%lu`
- `{"nucleus":"%I64d"}`

## Anti-Tamper / DRM Notes

- Denuvo anti-tamper is present
- Anti-tamper trigger: `futMatchTime = 0` when tampered (resets match time)
- Certificate pinning for `*.ea.com` and `*.easports.com`

## Key Internal References

- `CFUT_URL` — Likely a config variable holding the FUT server base URL
- `EASW-Version: 2.0.5.0` — The EASW API version used by FIFA 17
- Source path: `E:/p4/fifafb/rl/empatch/TnT/Code/fifa/gamemodes/extern/EAStore/3.00.00-fifa/source/metadatas/metanucleusassociation.cpp`
- License XML with CipherKey, MachineHash, ContentId, GameToken present in memory

## What We Need to Replicate

### Priority 1: Blaze Redirector
The game's first network call. Must respond with a valid server address.

### Priority 2: Blaze Server  
Handles authentication, matchmaking, and real-time game communication. Binary protocol (not HTTP).

### Priority 3: EASW/FUT HTTP API
The REST-like API that handles all Ultimate Team operations (squads, transfer market, packs, etc.). Uses the EASW-* headers.

### Priority 4: Content Server
Serves game assets, roster updates, and FUT card data.
