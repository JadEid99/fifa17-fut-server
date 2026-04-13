# FIFA 17 Private Server - Current Status

## BREAKTHROUGH: LSX Origin SDK Server Built

We built a full LSX protocol server (`server-standalone/lsx-origin-server.mjs`) that
replaces the STP Origin emulator on port 4216. This server:

1. Implements the Challenge/ChallengeResponse handshake (AES-128-ECB, verified against
   origin-sdk Rust crate test vectors)
2. Sends a `Login` event with `IsLoggedIn=true` — this tells the game "you're logged
   in to Origin" which should trigger the Blaze login flow
3. Handles `GetAuthCode` requests — returns auth codes the game needs for Blaze login
4. Handles all other Origin SDK requests (GetProfile, GetConfig, etc.)

**Tested end-to-end**: Challenge → ChallengeResponse → ChallengeAccepted → Login event
→ GetAuthCode request → AuthCode response. All crypto matches the Rust crate exactly.

## WHAT THIS SHOULD FIX

The core problem was: the game does PreAuth → close_notify → done, and NEVER sends
a Blaze Login request. We confirmed via x64dbg that the OriginRequestAuthCodeSync
function at 146f19a11 is NEVER called.

The hypothesis: the game's state machine requires a successful Origin SDK session
(Login event + auth tokens) before it will attempt a Blaze login. The STP emulator
only handles Denuvo licensing — it does NOT send Login events or handle GetAuthCode.

Our LSX server provides exactly what was missing.

## HOW TO TEST

Run `batch_test_lsx.ps1` on the Windows PC. It will:
1. Build and deploy the DLL
2. Disable the STP emulator (rename to .bak)
3. Start our LSX server on port 4216
4. Launch the game
5. Start the Blaze server
6. Trigger a connection attempt
7. Collect results and restore STP

**Two possible outcomes:**
- **Game starts normally**: Our LSX server handles both Denuvo and Origin auth.
  If the game then sends a Blaze Login → we've solved the core problem!
- **Game fails to start**: Denuvo needs something specific from STP that we don't
  provide. In that case, use proxy mode (--proxy) with STP on port 4217.

## FILES

- `server-standalone/lsx-origin-server.mjs` — LSX Origin SDK server (standalone + proxy modes)
- `server-standalone/test-lsx-client.mjs` — Test client (verified working)
- `batch_test_lsx.ps1` — Automated test script
- `server-standalone/server.mjs` — Blaze/TLS server (unchanged)
- `dll-proxy/dinput8_proxy.cpp` — DLL patches (unchanged)

## WHAT WORKS

- TLS 1.2 handshake with RC4-SHA (redirector + main server)
- Blaze PreAuth parsing and response
- DLL patches (cert bypass, Origin SDK check, auth code provider, auth flag)
- LSX Challenge/ChallengeResponse handshake
- LSX Login event + GetAuthCode handling
