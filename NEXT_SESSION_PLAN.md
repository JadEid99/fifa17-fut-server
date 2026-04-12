# FIFA 17 Private Server - STATUS UPDATE

## DEFINITIVE CONCLUSION
PreAuth → close_notify is HARDCODED behavior. The game ALWAYS closes after PreAuth.
Login happens on a SEPARATE connection that is never initiated because Origin auth fails.

Proven by:
- Real BF4 EA server response → same close_notify
- Proactive SilentLogin sent after PreAuth → game ignores it, still closes
- x64dbg: Origin auth function (146f19a11) NEVER called
- x64dbg: Only ONE winsock connect() call (to redirector 42230)
- Game makes exactly: redirector HTTP → main server PreAuth → close. That's it.

## THE REAL BLOCKER
The game needs the Origin SDK to provide an auth token. The STP emulator
handles Denuvo licensing but NOT Origin online auth. Without a real auth token,
the game never initiates the Login connection.

## SOLUTION OPTIONS
1. Write a replacement Origin SDK DLL (stp-origin_emu.dll replacement)
   that provides fake auth tokens
2. Patch the game's online state machine to skip to "logged in" state
3. Find and hook the specific function that initiates the Login connection
   and call it directly from our DLL

## FOR NEXT SESSION
- Option 2 is most promising: find the game's "online state" variable in Ghidra
  and patch it to "logged in" after PreAuth
- Search for strings like "LOGGED_IN" or "CONNECTED" or state values
- The game's FE (front-end) code at addresses 146f7xxxx manages online state
- FUN_146f7c7e0 at 146f7b279 calls the auth token request - trace its caller
  to find the state machine
