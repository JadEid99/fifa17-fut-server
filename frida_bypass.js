/**
 * Frida v4 - Dump code around SetCACert string references.
 * The SetCACert string at exe+0x39316B1 is referenced by the
 * ProtoSSLSetCACert function. Find the code that calls it.
 * 
 * Also: since debug strings are stripped, let's find the cert
 * verification by looking for the RSA signature check pattern.
 * 
 * Run: frida -n FIFA17.exe -l frida_bypass.js
 */
console.log("[*] FIFA 17 ProtoSSL Bypass v4");

var mod = Process.enumerateModules()[0];
var base = mod.base;
console.log("[*] " + mod.name + " base=" + base + " size=" + mod.size);

// Known addresses from previous scans
var setCACertStr = base.add(0x393169d); // "SetCACert" 
var installedCAStr = base.add(0x39316b1); // "installed CA cert"

// Dump the string area to see context
console.log("\n[*] Strings around SetCACert:");
console.log(hexdump(base.add(0x3931680), {length: 256, header: true, ansi: false}));

// Find code that references "installed CA cert" string (exe+0x39316B1)
// Search for LEA instructions with RIP-relative addressing to this address
console.log("\n[*] Searching for code referencing 'installed CA cert' at " + installedCAStr);

// The code is likely in the Denuvo-decrypted region around exe+0x6120000
// (from NEXT_SESSION_PLAN.md: SSL state machine at +0x6126213)
// Search that specific region
var searchStart = base.add(0x6100000);
var searchSize = 0x100000; // 1MB

console.log("[*] Searching code region " + searchStart + " to " + searchStart.add(searchSize));

var targetOffset = installedCAStr.sub(base);
console.log("[*] Target string offset from base: " + targetOffset);

try {
    var code = Memory.readByteArray(searchStart, searchSize);
    var view = new Uint8Array(code);
    var found = 0;
    
    for (var i = 0; i < view.length - 7; i++) {
        // LEA reg, [rip+disp32]
        if (view[i+1] !== 0x8D) continue;
        var prefix = view[i];
        if (prefix !== 0x48 && prefix !== 0x4C) continue;
        var modrm = view[i+2];
        if ((modrm & 0xC7) !== 0x05) continue;
        
        var disp = (view[i+3] | (view[i+4] << 8) | (view[i+5] << 16) | (view[i+6] << 24));
        if (disp > 0x7FFFFFFF) disp -= 0x100000000;
        
        var instrAddr = searchStart.add(i);
        var refTarget = instrAddr.add(7).add(disp);
        
        // Check if it references our target string
        if (refTarget.equals(installedCAStr)) {
            console.log("\n[+] FOUND: Code at " + instrAddr + " references 'installed CA cert'");
            console.log("[+] Offset from exe base: " + instrAddr.sub(base));
            
            // Dump 128 bytes before and 64 bytes after
            console.log("\n[*] Code context (256 bytes around reference):");
            console.log(hexdump(instrAddr.sub(128), {length: 256, header: true, ansi: false}));
            found++;
        }
        
        // Also check for SetCACert references
        if (refTarget.equals(setCACertStr)) {
            console.log("\n[+] FOUND: Code at " + instrAddr + " references 'SetCACert'");
            console.log("[+] Offset: " + instrAddr.sub(base));
            console.log(hexdump(instrAddr.sub(64), {length: 128, header: true, ansi: false}));
            found++;
        }
    }
    
    if (found === 0) {
        console.log("[-] No code references found in this region");
        console.log("[*] Trying broader search...");
        
        // Try the region around the known cert verify address +0x6124140
        var searchStart2 = base.add(0x6120000);
        var code2 = Memory.readByteArray(searchStart2, 0x20000);
        var view2 = new Uint8Array(code2);
        
        // Just dump the cert verify function area
        console.log("\n[*] Dumping code at known cert verify offset +0x6124140:");
        console.log(hexdump(base.add(0x6124140), {length: 128, header: true, ansi: false}));
        
        console.log("\n[*] Dumping code at known cert process offset +0x6127020:");
        console.log(hexdump(base.add(0x6127020), {length: 128, header: true, ansi: false}));
        
        console.log("\n[*] Dumping code at known State 3 (Certificate) offset +0x61262DC:");
        console.log(hexdump(base.add(0x61262DC), {length: 128, header: true, ansi: false}));
    }
} catch(e) {
    console.log("[-] Error: " + e);
}

console.log("\n[*] Done.");
