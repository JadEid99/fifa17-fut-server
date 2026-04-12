# FIFA 17 Private Server - DETAILED STATUS

## WHAT WORKS
- DLL v55: 3 patches (cert bypass, Origin SDK, auth flag bypass) - all apply successfully
- TLS handshake on redirector (42230) and main server (10041)
- HTTP redirect over TLS on redirector
- PreAuth request decoded correctly (CDAT, CINF, FCCR, LADD)
- PreAuth response sent with correct TDF encoding (varint fixed)
- Game parses our PreAuth (confirmed by "servers shut down" message when hosts not redirected)

## THE BLOCKER
Game sends PreAuth on main server (10041), receives our response, then sends
TLS close_notify and disconnects. Never sends Login/SilentLogin.

## WHAT WE'VE TRIED (all same result)
- Different PreAuth response bodies (empty, minimal, full, different fields)
- Different header formats (msgType at offset 4, offset 12, packed)
- nucleusConnect/nucleusProxy URLs (real EA, localhost:8080)
- Origin SDK bypass (always return true)
- Auth flag bypass (set [RSI+0xe8]=1, skip auth code request)
- Longer wait times (25s, 60s)
- Extra hosts file entries
- Catch-all port listeners (443, 80, 9988, 17502, 9946)

## KEY OBSERVATIONS
1. Connection monitor: main server stays ESTABLISHED for ~10 seconds after PreAuth
2. Redirector connection stays ESTABLISHED for 30+ seconds (never closes)
3. STP emulator (port 4216) connection unchanged throughout
4. No connections to any other ports
5. Game's PreAuth request includes: SVCN="fifa-2017-pc", ENV="prod", CLNT="FIFA17"
6. close_notify MAC verified correct - game intentionally closes

## POSSIBLE REMAINING CAUSES
1. The game might need a SPECIFIC PreAuth response that we're not providing
   - Maybe INST should be "fifa-2017-pc" (matching SVCN from request)
   - Maybe we need more CIDS (component IDs)
   - Maybe the CONF map encoding is subtly wrong despite looking correct
2. The game might do Login on the REDIRECTOR connection (HTTP), not main server
3. The game might need the server to send something FIRST (notification/ping)
4. The STP emulator might need to return something specific that our patches don't cover
5. There might be ANOTHER auth check we haven't found

## NEXT APPROACH TO TRY
- Use x64dbg on Windows to set breakpoints and trace the actual execution flow
  after PreAuth response is received. This would definitively show what code runs
  and where it decides to close the connection.
- OR: Try matching INST to "fifa-2017-pc" and adding more CIDS
