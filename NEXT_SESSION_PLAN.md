# FIFA 17 Private Server - Session Status

## BREAKTHROUGH: Connection stays open after PreAuth!

v80 NOPs the disconnect call in the PreAuth completion handler (FUN_146e19a00).
For the first time, the game stays connected after PreAuth and sends additional
data (comp=0x0000 cmd=0x0000 — a keepalive/ping).

Previously: PreAuth → immediate close_notify → disconnect (every single test)
Now: PreAuth → keepalive packet → then disconnect

## What's working (8 patches)
1. Cert bypass (JNZ→JMP)
2. Origin SDK availability (always true)
3. FUN_1470db3c0 body (fake auth code provider)
4. Telemetry auth flag
5. IsLoggedIntoEA (always true)
6. IsLoggedIntoNetwork (always true)
7. SDK gate FUN_1471a5da0 (always return 1) — unblocks login flow
7b. PreAuth completion handler (NOP disconnect call) — keeps connection open
8. Fake SDK manager object at DAT_144b86bf8 with vtable stubs
9. Auth request re-injection (cave executes, auth code stored)

## Root cause found
DAT_144b86bf8 (Origin SDK manager) is NULL. The STP emulator doesn't create it.
This blocks FUN_1471a5da0 which gates the entire login flow.
We create a fake object with vtable stubs and patch the gate function.

## Next steps
1. The game sends a keepalive (comp=0 cmd=0) after PreAuth but then disconnects.
   Need to understand what the game expects next — possibly PostAuth or Login.
2. The Blaze SDK's connection state machine may need more conditions satisfied
   before it proceeds to Login.
3. The fake SDK object's vtable[0x188] returns the Blaze hub dynamically.
   Need to verify this works when the game actually calls it.

## Key addresses (fixed, no ASLR)
- FUN_1471a5da0: SDK gate (patched to return 1)
- FUN_146e19a00: PreAuth completion handler (disconnect NOPed at +61)
- FUN_146f2a270: Login sender (called via callback, not directly)
- FUN_146f39b20: "Go online" function (Q key trigger)
- DAT_144b86bf8: Origin SDK manager (NULL, we write fake object)
- DAT_1448a3b20: OnlineManager pointer
- DAT_1448a3ac3: Online mode flag (1 = active)
