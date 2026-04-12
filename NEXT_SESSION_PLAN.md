# FIFA 17 Private Server - STATUS (April 12, 2026)

## CRITICAL FINDINGS FROM BF4 BLAZE EMULATOR ANALYSIS

### 1. Varint Encoding Bug (FIXED in v45)
The TDF varint continuation bit was WRONG. Our encoder used 0x40 (bit 6) for the
first byte's continuation, but EA's format uses 0x80 (bit 7) on ALL bytes.
This means EVERY value >= 64 in our PreAuth response was encoded incorrectly.
The game couldn't parse the response properly.

### 2. Missing nucleusConnect/nucleusProxy URLs (FIXED in v45)
The BF4 emulator's PreAuth response includes critical CONF map entries:
- nucleusConnect: https://accounts.ea.com
- nucleusProxy: https://gateway.ea.com
These are the URLs the game uses for Origin authentication after PreAuth.
Without them, the game can't proceed to Login.

### 3. Header Format
BF4 uses 12-byte headers. FIFA 17 appears to use 16-byte (Fire2) headers.
The BF4 emulator's large packet handling adds extra size bytes, which may
be the Fire2 format. Need to verify if FIFA 17 really uses 16 or 12 bytes.

## READY TO TEST
v45 has both fixes. Run: git pull && .\batch_test.ps1

## IMPORTANT: Hosts File
The hosts file was modified to redirect EA hostnames. Only keep:
127.0.0.1 winter15.gosredirector.ea.com
Remove all other EA hostname redirects to avoid breaking the EA app.
