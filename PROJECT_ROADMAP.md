# FIFA 17 Ultimate Team Private Server — Project Roadmap

## What We Know

### Existing Open Source Projects We Can Build On

1. **PocketRelay** (Rust) — https://github.com/PocketRelay/Server
   - Full Blaze server emulator for Mass Effect 3
   - Already implements: Blaze redirector, Blaze main server, QoS server, HTTP server
   - Uses HTTP Upgrade to tunnel Blaze protocol over a single port
   - Has client-side redirector that patches hosts file
   - **This is our best reference for the Blaze layer**

2. **ME3PSE** (C#) — https://github.com/PrivateServerEmulator/ME3PSE
   - Earlier Mass Effect 3 private server emulator
   - Implements Blaze protocol parsing, packet viewer
   - Good reference for understanding Blaze packet structure

3. **futapi/fut** (Python) — https://github.com/futapi/fut
   - FUT Web App API client library
   - Documents all EASW/FUT HTTP API endpoints (search, bid, sell, packs, squads, etc.)
   - **This is our best reference for the FUT API layer**

4. **trydis/FIFA-Ultimate-Team-Toolkit** (C#) — https://github.com/trydis/FIFA-Ultimate-Team-Toolkit
   - Another FUT API client with documented endpoints

### Architecture We Need to Build

```
┌─────────────────┐     ┌──────────────────────────────────────────┐
│   FIFA 17 PC    │     │           Our Private Server              │
│                 │     │                                          │
│  ┌───────────┐  │     │  ┌─────────────┐  ┌──────────────────┐  │
│  │ Blaze     │──┼─────┼─>│ Redirector  │  │ Blaze Main       │  │
│  │ Client    │  │     │  │ (port 42127)│─>│ Server           │  │
│  └───────────┘  │     │  └─────────────┘  │ - Auth           │  │
│                 │     │                    │ - Matchmaking    │  │
│  ┌───────────┐  │     │                    │ - Game Sessions  │  │
│  │ EASW/FUT  │──┼─────┼─────────────────> │                  │  │
│  │ HTTP API  │  │     │                    └──────────────────┘  │
│  └───────────┘  │     │                                          │
│                 │     │  ┌──────────────────┐                    │
│  ┌───────────┐  │     │  │ FUT HTTP API     │                    │
│  │ Nucleus   │──┼─────┼─>│ - Squads         │                    │
│  │ Auth      │  │     │  │ - Transfer Market │                    │
│  └───────────┘  │     │  │ - Packs          │                    │
│                 │     │  │ - SBCs           │                    │
└─────────────────┘     │  │ - Leaderboards   │                    │
                        │  └──────────────────┘                    │
                        │                                          │
                        │  ┌──────────────────┐                    │
                        │  │ Database          │                    │
                        │  │ - Player cards    │                    │
                        │  │ - User accounts   │                    │
                        │  │ - Market state    │                    │
                        │  └──────────────────┘                    │
                        └──────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: Blaze Redirector + Auth Bypass (Get past the main menu)
**Goal**: Game connects to our server and doesn't error out

1. Build a Blaze redirector that listens on port 42127
   - Reference: PocketRelay's redirector implementation
   - Must respond to the initial `redirectorGetServerInstance` request
   - Returns our Blaze main server address

2. Build a minimal Blaze main server
   - Handle the initial TLS handshake (EA uses custom SSLv3)
   - Reference: PocketRelay's `blaze-ssl-async` crate
   - Respond to authentication packets with success
   - Handle `preAuth`, `postAuth`, `login` Blaze components

3. Client-side: Redirect FIFA 17 to our server
   - Modify Windows hosts file: `127.0.0.1 winter15.gosredirector.ea.com`
   - Or patch the binary to point to our server

**Success criteria**: FIFA 17 gets past "Connecting to EA servers" screen

### Phase 2: FUT Entry (Get into Ultimate Team mode)
**Goal**: Navigate into FUT from the main menu

1. Handle FUT-specific Blaze messages
   - `futBlazeLogin` flow
   - Nucleus authentication stubs
   - Return valid session tokens

2. Stub the EASW HTTP API
   - Respond to initial FUT data requests
   - Return empty/default squad data
   - Handle roster check requests

**Success criteria**: FUT main hub loads without crashing

### Phase 3: Core FUT Features
**Goal**: Basic Ultimate Team functionality works

1. **Squad Management**
   - Load/save squads
   - Player positioning
   - Chemistry calculation

2. **Player Card Database**
   - Import FIFA 17 player database (available from community sources)
   - Card attributes, ratings, positions
   - Special card types (TOTW, TOTS, etc.)

3. **Pack Opening**
   - Server-side RNG for card generation
   - Pack types and probabilities
   - Coin/point economy

4. **Transfer Market**
   - List items for auction
   - Search/filter
   - Bid and Buy Now
   - Market price tracking

### Phase 4: Multiplayer & Polish
**Goal**: Play matches against other users on the server

1. **Matchmaking**
   - Division-based matchmaking
   - FUT Champions qualification
   - Draft mode

2. **Match Result Processing**
   - Coin rewards
   - Player contracts
   - Injury system

3. **Squad Building Challenges**
   - SBC templates
   - Requirement validation
   - Rewards

## Tech Stack Recommendation

- **Language**: Rust (following PocketRelay's proven approach) or TypeScript/Node.js (faster to prototype)
- **Blaze Protocol**: Fork/adapt PocketRelay's Blaze implementation
- **FUT API**: Custom HTTP server (Express/Actix-web)
- **Database**: PostgreSQL (player data, user accounts, market)
- **Hosting**: AWS EC2 or ECS

## Key FIFA 17-Specific Details (from our memory dump)

- Blaze redirector: `winter15.gosredirector.ea.com:42230`
- EASW API version: `2.0.5.0`
- FUT API base URL stored in `CFUT_URL` config variable
- EASW headers: Session, Token, Nucleus-Persona, Request-Signature, Userid, Version
- Auth flow: Origin → Blaze → Nucleus → EASW session
- Anti-tamper: Denuvo + custom triggers (futMatchTime reset)
- Certificate pinning for `*.ea.com` and `*.easports.com` (needs bypass)
- FUT online assets endpoint: `http://89.234.41.144:8080/onlineAssets/2012/fut`
- UTAS endpoint pattern: `utas.mob.v4.fut.ea.com` (from web research)

## Next Immediate Steps

1. **Set up mitmproxy** on your PC to capture the actual Blaze packets FIFA 17 sends
2. **Fork PocketRelay** and start adapting it for FIFA 17's Blaze variant
3. **Study the futapi/fut Python library** to understand all FUT API endpoints
4. **Build Phase 1** — get past the connection screen
