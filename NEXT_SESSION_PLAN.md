# FIFA 17 Private Server - End of Day 3 Status

## What We Know For Certain

1. **DAT_144b86bf8 = NULL** — The Origin SDK manager is never created by the STP emulator.
   This blocks `FUN_1471a5da0` (returns 0) which gates the entire login flow.

2. **The Blaze flow is: PreAuth → disconnect → callback → Login on new connection.**
   PreAuth and Login happen on SEPARATE TCP connections. This is by design.

3. **The post-PreAuth callback chain requires `BlazeHub+0x53f = 1`.**
   We force this flag, but the callback still doesn't trigger Login.

4. **All 3 login type vtable[0x10] functions point to the same code (`0x146E156A0`).**
   We patched it to return 1. This should allow the callback to proceed.

5. **The auth token is stored in a temporary request object that gets destroyed.**
   The Blaze SDK never reads it because the destructor (which should transfer it)
   uses our fake vtable with RET stubs.

6. **The PreAuth NOP keeps the connection open** — game sends a keepalive then disconnects.
   But no Login is sent on the open connection.

## What's NOT Working

The post-PreAuth callback fires (`FUN_146da9570` schedules `FUN_146dad43c`) but
the Login connection is never initiated. Despite:
- SDK gate returning 1
- All login type vtables returning 1
- BlazeHub+0x53f = 1
- Fake SDK object in place
- Auth token stored (cave executes)

## Remaining Options

### Option A: Find the EXACT remaining blocker in the callback chain
Trace `FUN_146dad43c` → vtable dispatch → what function is called → what it checks.
This requires more Ghidra analysis. Could find the answer or could find yet another flag.

### Option B: Patch the game binary to skip auth entirely
Find the function that decides "send Login or disconnect" and patch it to always
send Login. This is what BF3 blaze-server did (patched exe). Requires finding the
exact decision point in the Blaze SDK's connection state machine.

### Option C: Build a more complete Origin emulator
Replace the STP emulator with one that creates a proper Origin SDK manager object
(DAT_144b86bf8) with all the right vtable entries. This would make the game's
natural flow work without any patches. Very complex.

### Option D: Intercept at the network level
Instead of patching the game, intercept the Blaze protocol at the network level.
When the game sends PreAuth, our proxy responds AND immediately sends a Login
request on behalf of the game. The server processes both and sends back session data.
This requires understanding the exact Login request format.

## Recommendation
Option B is the most direct. We need to find the ONE function in the Blaze SDK
that decides "I have auth, proceed to Login" vs "no auth, disconnect." We've been
patching around it but haven't found it yet. The Ghidra export has the answer —
we just need to trace the right path.
