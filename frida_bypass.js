// v24: Find ALL ProtoSSLRefT structs and set bAllowAnyCert (+0xC20) = 1
// Do this BEFORE the connection attempt, not during it.
// The struct has "winter15.gosredirector.ea.com" at the strHost field.
// bAllowAnyCert is at strHost + 0xC20 - strHost_offset.
// From the code: CMP BYTE [rbx+0xC20], 0 is the check.
// rbx is the struct base. strHost is at some offset from struct base.
// From v22: strHost was at 0x27dd0c58, sockaddr at strHost+0x100.
// If sockaddr is at struct+0x110 (for example), strHost is at struct+0x10.
// Then bAllowAnyCert at struct+0xC20 = strHost + 0xC20 - 0x10 = strHost + 0xC10.
// But we don't know the exact strHost offset.
//
// SIMPLER: just search for ALL bytes at offset +0xC20 from any struct-like
// region that contains "winter15" and set them to 1.
// OR: search memory for the byte pattern 80 BB 20 0C 00 00 00 (the CMP instruction)
// and NOP it. Wait - that's in encrypted code, we already tried Frida for that.
//
// ACTUALLY: We CAN use Frida to patch the code. We did it successfully before!
// The bAllowAnyCert check is at exe+0x6127C22:
//   80 BB 20 0C 00 00 00  CMP BYTE [rbx+0xC20], 0
//   75 18                  JNE +0x18 (skip error if != 0)
//
// If we change the JNE (75) to JMP (EB), it ALWAYS skips the error.
// We tried this in batch v6 test A1 and got ECONNRESET.
// BUT that was because there's ANOTHER check elsewhere.
//
// The key insight from our batch tests:
// - Patching cert_receive alone → ECONNRESET (another check catches it)
// - NOP-ing +0x612644E alone → HANGING (prevents disconnect but no key exchange)
// - We need BOTH: skip the cert error AND prevent the later disconnect
//
// What if we combine: JMP at +0x6127C29 AND NOP at +0x612644E?
// We tested this as B1 in batch v6 and got... HANGING.
//
// The HANGING means the game doesn't disconnect but also doesn't send data.
// This is because the cert was rejected, so the public key wasn't extracted,
// so the game can't create the ClientKeyExchange.
//
// THE REAL SOLUTION: We need the cert to be PARSED (to extract the public key)
// but the VERIFICATION to be skipped.
//
// In the DirtySDK source, _ProtoSSLUpdateRecvServerCert does:
//   1. _ParseCertificate() → extracts public key, issuer, subject
//   2. if (!bAllowAnyCert) { hostname check + _VerifyCertificate() }
//
// If bAllowAnyCert is set, step 2 is SKIPPED but step 1 still runs.
// The public key IS extracted. The handshake CAN proceed.
//
// So setting bAllowAnyCert SHOULD work. The problem is we couldn't set it
// at the right time. But now we know the struct address from v22.
//
// Let's try: find the struct, set byte at +0xC20 to 1, THEN trigger connection.

console.log("[*] v24 - set bAllowAnyCert on all structs BEFORE connection");

var pattern = "77 69 6E 74 65 72 31 35 2E 67 6F 73 72 65 64 69 72 65 63 74 6F 72 2E 65 61 2E 63 6F 6D";
var found = 0;

Process.enumerateRanges('rw-').forEach(function(range) {
    if (range.size < 0x1000) return;
    try {
        Memory.scanSync(range.base, range.size, pattern).forEach(function(match) {
            var strHost = match.address;
            
            // Check for sockaddr at strHost+0x100 (family=2, ip=127.0.0.1)
            try {
                if (strHost.add(0x100).readU16() !== 2) return;
            } catch(e) { return; }
            
            found++;
            console.log("[+] Struct #" + found + ": strHost at " + strHost);
            
            // bAllowAnyCert is at [rbx+0xC20] where rbx is struct base.
            // We need to figure out what offset strHost is at from struct base.
            // From v22: values of 1 at strHost-232,-196,-160,-124
            // strHost-124 = strHost-0x7C. If this is iState at struct+0x8C,
            // then struct_base = strHost - 0x7C - 0x8C = strHost - 0x108.
            // Wait: strHost-0x7C has value at struct+0x8C means:
            //   struct_base + 0x8C = strHost - 0x7C
            //   struct_base = strHost - 0x7C - 0x8C = strHost - 0x108
            // Then bAllowAnyCert = struct_base + 0xC20 = strHost - 0x108 + 0xC20 = strHost + 0xB18
            
            // But let's also try other interpretations:
            // If strHost is at struct+0x20 (from old source): struct_base = strHost - 0x20
            //   bAllowAnyCert = strHost - 0x20 + 0xC20 = strHost + 0xC00
            // If strHost is at struct+0x100: struct_base = strHost - 0x100
            //   bAllowAnyCert = strHost - 0x100 + 0xC20 = strHost + 0xB20
            
            var offsets = [0xB18, 0xB20, 0xC00, 0xC10, 0xC20];
            offsets.forEach(function(off) {
                try {
                    var val = strHost.add(off).readU8();
                    console.log("  strHost+0x" + off.toString(16) + " = 0x" + val.toString(16));
                    strHost.add(off).writeU8(1);
                    console.log("  SET to 1");
                } catch(e) {
                    console.log("  strHost+0x" + off.toString(16) + " = ERROR: " + e.message);
                }
            });
        });
    } catch(e) {}
});

console.log("[*] Set bAllowAnyCert on " + found + " structs. Now press Q to connect.");
