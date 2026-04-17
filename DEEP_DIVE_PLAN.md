# FIFA 17 — Strategic Reset (After 21 Failed Tests)

## What We Proved Doesn't Work

Every approach that manipulates the game from inside has failed:
- Injecting into +0x218 array → crash (TDF vtable needed)
- Calling LoginSender from various contexts → deadlock / crash / queued but never dispatched
- Returning 1 from LoginCheck → Logout still fires at 30s
- Fixing CreateAccount response → game doesn't send CreateAccount in our setup

The game's BlazeSDK is too tightly coupled. We cannot fight it from the inside.

## What We Need: External Reference Sources

### DISCOVERED: ZamboniDevelopment (github.com/ZamboniDevelopment)

This organization has a complete, working ecosystem of Blaze server emulators:

| Repo | Purpose | Relevance |
|------|---------|-----------|
| **BlazeSDK** | C# Blaze SDK with full TDF schemas | All RPC structures defined |
| **Zamboni** | NHL 10 server (Blaze v1?) | Same protocol family |
| **Zamboni11** | NHL 11 server | Recently updated |
| **Zamboni3** | NHL 12-15 server | Closest to FIFA 17 era |
| **Zamboni14Legacy** | NHL 14 (uses Blaze3SDK) | Has working PreAuth |
| **ZamboniUltimateTeam** | 🎯 **FUT BACKEND!** | Updated 2 days ago |
| **ZamboniCommonComponents** | Shared Blaze components | Common RPCs |
| **Taggi** | 🎯 **TDF tag binary parser** | Solves our tag problem |
| **TheDirector** | Redirector service | Reference |
| **Skateboard3Server.Qos** | QoS server | Reference |
| **ppu-patches** | RPCS3 game patches | Reference for binary patching |

### CRITICAL FINDING: PreAuthResponse structure (from Zamboni14Legacy)

```csharp
new PreAuthResponse
{
    mAuthenticationSource = "303107",
    mComponentIds = [1, 4, 5, 7, 9, 10, 11, 13, 15, 21, 25, 28, 2249, 2250, 2251, 2262, 2268, 30722],
    mConfig = new FetchConfigResponse { mConfig = {...} },
    mEEFA = true,                    // ← NEW FIELD we don't send!
    mESRC = "nhl-2016-ps3",
    mINST = "nhl-2016-ps3",
    mUnderageSupported = false,
    mPersonaNamespace = "cem_ea_id",
    mLegalDocGameIdentifier = "nhl-2016-ps3",   // ← NEW FIELD
    mPlatform = "ps3",
    mQosSettings = new QosConfigInfo { ... },
    mRegistrationSource = "303107",
    mServerVersion = Program.Name
}
```

**These are the FIELD NAMES**, not TDF tags. The C# SDK maps them to tags internally.
Using this SDK, we could generate properly-formatted PreAuth responses without
needing to know the exact TDF tag bytes.

### Architecture of Working Zamboni NHL 14 Auth Flow

From `AuthenticationComponent.cs`:

1. PreAuth returns above response
2. Game sends `Ps3Login` (or `Login` on PC) with auth ticket
3. Server validates ticket, creates `UserSessionExtendedData`, `UserIdentification`, `SessionInfo`
4. Server returns `ConsoleLoginResponse` with session data
5. Server sends 4 async notifications on a delayed timer:
   - `NotifyUserAuthenticated` (300ms)
   - `NotifyUserAdded` (500ms)
   - `NotifyUserSessionExtendedDataUpdate` (600ms)
   - `NotifyUserUpdated` (800ms)

**This is the correct full login flow.** We've been missing the notifications.

## The Real Plan

### Step 1: Clone and analyze the Zamboni ecosystem
Get the BlazeSDK, Zamboni14Legacy, ZamboniCommonComponents, and ZamboniUltimateTeam
repos. Use Zamboni14Legacy as the reference working implementation.

### Step 2: Adapt Zamboni's PreAuth response for FIFA 17
Replace our hand-crafted PreAuth with one that matches Zamboni's structure,
using the C# SDK's TDF encoder. The BlazeSDK C# library handles all the
TDF tag encoding internally.

Either:
- (A) Port the Zamboni PreAuth builder to Node.js/TypeScript, OR
- (B) Run Zamboni14Legacy as our Blaze server (it's already a working server)

Option B is probably fastest — we already have Origin IPC working, we just
need to swap out the Blaze server.

### Step 3: Customize for FIFA 17
Change identifiers:
- `mESRC`, `mINST`, `mLegalDocGameIdentifier` → `fifa-2017-pc`
- `mPlatform` → `pc`
- `mComponentIds` → FIFA 17's specific component list (we know some from our logs)

### Step 4: Use Taggi to dump FIFA 17's TDF schema
`Taggi` parses TDF tags from binaries. Run it on FIFA17.exe to extract the
exact PreAuthResponse schema (14 fields, with their TDF tags).

### Step 5: Leverage ZamboniUltimateTeam for FUT endpoints
After login works, we'll need FUT-specific RPCs. ZamboniUltimateTeam has
Ultimate Team backend code (for NHL HUT). The structure is similar to
FIFA FUT — squad management, transfer market, packs, SBCs.

## Why This Plan Will Work

- **We stop fighting the BlazeSDK.** We use a properly-structured PreAuth
  response that the game accepts natively. No Frida, no DLL patches needed
  for the login flow.
- **We use a battle-tested emulator.** Zamboni NHL servers actually work —
  people connect NHL 10-15 consoles to them and play. The architecture is proven.
- **We get the login notifications right.** The 4 async notifications after
  Login are critical. We've never sent these.
- **We have a roadmap for FUT.** ZamboniUltimateTeam shows how to implement
  the post-login FUT backend.

## Timeline

- Phase 1: Clone Zamboni repos, understand the code (30 min)
- Phase 2: Get Zamboni14Legacy building locally (1 hour)
- Phase 3: Configure it for FIFA 17 (1 hour)
- Phase 4: Test with FIFA 17 (30 min)
- Phase 5: Debug any FIFA-specific issues (variable)

This approach is fundamentally different from everything we've tried.
Instead of bypassing or manipulating the BlazeSDK, we SPEAK its language
correctly using a proven working implementation.
