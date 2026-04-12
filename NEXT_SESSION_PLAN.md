# FIFA 17 SSL Bypass - Current Status

## KEY FINDING: Timing Issue

Our Frida patches are applied AFTER the game has already started the SSL handshake. The game's first connection attempt happens during launch (before we press Q). By the time we apply patches and press Q for attempt #2, the code may have already been executed on attempt #1 and the patches don't affect the cached state.

## What We Know Works
- 3x bAllowAnyCert JNE→JMP patches prevent the disconnect (HANGING result)
- The game DOES read our TLS response (ECONNRESET proves it processes the data)
- The memory dump has all decrypted code

## What We Need To Do
1. Apply Frida patches DURING game launch (before first connection attempt)
2. Or use the DLL proxy to apply patches at DLL_PROCESS_ATTACH time
3. The DLL approach is better because it runs before ANY game code executes

## Patch Locations (confirmed from dump)
- bAllowAnyCert check 1: exe+0x612522D (change 75→EB)
- bAllowAnyCert check 2: exe+0x612753D (change 75→EB)  
- bAllowAnyCert check 3: exe+0x6127C29 (change 75→EB)

## Architecture
- cert_receive (+0x6127B40): reads cert data from socket
- cert_process (+0x6127020): parses TLS record fragments (NOT cert verification)
- cert_finalize (+0x61279F0): finalizes cert processing
- State 3 handler (+0x61262DC): orchestrates cert receive/process/verify
- +0x6124140: called on success path (hostname check?)
- +0x612E770: error handler (calls disconnect)
- +0x612D5D0: disconnect function

## The Plan
Use the dinput8.dll proxy to scan for the bAllowAnyCert byte patterns in memory
and patch them as soon as Denuvo decrypts the code. This happens before the game
tries to connect, so the patches are in place for the first connection attempt.
