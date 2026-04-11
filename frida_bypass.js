/**
 * Frida v6 - Fixed API calls. Patch cert verify.
 * Run: frida -n FIFA17.exe -l frida_bypass.js
 */
console.log("[*] FIFA 17 ProtoSSL Bypass v6");

var base = Process.enumerateModules()[0].base;
console.log("[*] Base: " + base);

var certVerify = base.add(0x6124140);
console.log("[*] cert_verify target: " + certVerify);

// Check if the page is mapped
try {
    var testByte = certVerify.readU8();
    console.log("[+] Address readable, first byte: 0x" + testByte.toString(16));
    
    // Read 32 bytes
    var bytes = [];
    for (var i = 0; i < 32; i++) {
        bytes.push(certVerify.add(i).readU8().toString(16).padStart(2, '0'));
    }
    console.log("[*] cert_verify bytes: " + bytes.join(' '));
    
    // Check if it's real code
    if (testByte === 0 || testByte === 0xCC) {
        console.log("[-] Looks like uninitialized code");
    } else {
        console.log("[+] Looks like valid code, patching...");
        Memory.protect(certVerify, 16, 'rwx');
        certVerify.writeU8(0x31);       // xor eax, eax
        certVerify.add(1).writeU8(0xC0);
        certVerify.add(2).writeU8(0xC3); // ret
        console.log("[+] PATCHED! cert_verify now returns 0 (success)");
    }
} catch(e) {
    console.log("[-] Cannot access cert_verify: " + e.message);
    console.log("[*] Trying to find it via memory scan instead...");
    
    // The address might be wrong. Let's check what's at that virtual address.
    try {
        var info = Process.findRangeByAddress(certVerify);
        if (info) {
            console.log("[*] Range: " + info.base + " size=" + info.size + " prot=" + info.protection);
        } else {
            console.log("[-] Address not in any mapped range");
            
            // List all ranges near this address
            Process.enumerateRanges('---').forEach(function(r) {
                if (r.base.compare(certVerify.sub(0x1000000)) > 0 && 
                    r.base.compare(certVerify.add(0x1000000)) < 0) {
                    console.log("  Range: " + r.base + " size=" + r.size + " prot=" + r.protection);
                }
            });
        }
    } catch(e2) {
        console.log("[-] " + e2.message);
    }
}

// Also try the other known addresses
[0x6127020, 0x61262DC, 0x612E7A4, 0x612D5D0].forEach(function(off) {
    var addr = base.add(off);
    try {
        var b = addr.readU8();
        console.log("[+] exe+0x" + off.toString(16) + " readable, byte=0x" + b.toString(16));
    } catch(e) {
        console.log("[-] exe+0x" + off.toString(16) + " NOT accessible");
    }
});

console.log("\n[*] Done.");
