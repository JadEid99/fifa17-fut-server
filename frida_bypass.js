/**
 * Frida script to bypass ProtoSSL cert verification in FIFA 17.
 * 
 * Run AFTER the game has loaded (wait ~20 seconds):
 *   frida -n FIFA17.exe -l frida_bypass.js
 * 
 * This finds the cert verification error string and patches the
 * calling function to skip verification entirely.
 */

console.log("[*] FIFA 17 ProtoSSL Bypass");

// Step 1: Find "x509 cert untrusted" string in memory
var targetStr = "x509 cert untrusted";
var strAddr = null;

Process.enumerateRanges('r--').forEach(function(range) {
    if (strAddr) return;
    try {
        Memory.scanSync(range.base, range.size, 
            "78 35 30 39 20 63 65 72 74 20 75 6E 74 72 75 73 74 65 64"
        ).forEach(function(match) {
            strAddr = match.address;
        });
    } catch(e) {}
});

if (!strAddr) {
    console.log("[-] Could not find 'x509 cert untrusted' string. Is Denuvo unpacked?");
    // Try waiting and scanning again
} else {
    console.log("[+] Found string at: " + strAddr);
}

// Step 2: Find "certificate not issued to this host" - this is the hostname check
var hostCheckStr = null;
Process.enumerateRanges('r--').forEach(function(range) {
    if (hostCheckStr) return;
    try {
        Memory.scanSync(range.base, range.size,
            "63 65 72 74 69 66 69 63 61 74 65 20 6E 6F 74 20 69 73 73 75 65 64"
        ).forEach(function(match) {
            hostCheckStr = match.address;
        });
    } catch(e) {}
});

if (hostCheckStr) {
    console.log("[+] Found 'certificate not issued' at: " + hostCheckStr);
}

// Step 3: Find code that references these strings
// In x64, LEA with RIP-relative: 48 8D xx [4-byte displacement]
// or just 4C 8D / 8D with various prefixes
if (strAddr) {
    console.log("[*] Searching for code referencing the cert error strings...");
    
    var found = false;
    Process.enumerateRanges('r-x').forEach(function(range) {
        if (found) return;
        if (range.size > 0x10000000) return; // skip huge ranges
        try {
            var buf = Memory.readByteArray(range.base, range.size);
            var view = new Uint8Array(buf);
            
            for (var i = 0; i < view.length - 7; i++) {
                // Check for LEA with RIP-relative addressing
                // 48 8D 0D/15/05/3D xx xx xx xx (LEA rcx/rdx/rax/rdi, [rip+disp])
                // 4C 8D 05/0D/15 xx xx xx xx (LEA r8/r9/r10, [rip+disp])
                var prefix = view[i];
                var opcode = view[i+1];
                if ((prefix !== 0x48 && prefix !== 0x4C) || opcode !== 0x8D) continue;
                
                var modrm = view[i+2];
                if ((modrm & 0xC7) !== 0x05) continue; // must be [rip+disp32]
                
                var disp = view[i+3] | (view[i+4] << 8) | (view[i+5] << 16) | (view[i+6] << 24);
                if (disp > 0x7FFFFFFF) disp = disp - 0x100000000;
                
                var instrAddr = range.base.add(i);
                var targetAddr = instrAddr.add(7).add(disp);
                
                if (targetAddr.equals(strAddr)) {
                    console.log("[+] Code references 'x509 cert untrusted' at: " + instrAddr);
                    
                    // This instruction is inside _ProtoSSLUpdateRecvServerCert
                    // The bAllowAnyCert check is earlier in the function.
                    // Let's find the function start by looking backwards for common prologue
                    
                    // Dump 256 bytes before this instruction
                    console.log("[*] Code before the error string reference:");
                    console.log(hexdump(instrAddr.sub(256), {length: 256, header: true, ansi: false}));
                    
                    // Also dump 64 bytes after
                    console.log("[*] Code at and after the reference:");
                    console.log(hexdump(instrAddr, {length: 64, header: true, ansi: false}));
                    
                    found = true;
                    break;
                }
                
                if (hostCheckStr && targetAddr.equals(hostCheckStr)) {
                    console.log("[+] Code references 'certificate not issued' at: " + instrAddr);
                    console.log(hexdump(instrAddr.sub(128), {length: 192, header: true, ansi: false}));
                    found = true;
                    break;
                }
            }
        } catch(e) {}
    });
    
    if (!found) {
        console.log("[-] Could not find code referencing the error strings");
        console.log("[*] The strings might be in Denuvo-decrypted memory with different protection");
    }
}

console.log("[*] Script complete. Check output above.");
