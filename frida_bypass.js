/**
 * Frida v5 - Dump code at known SSL addresses and patch cert verify.
 * Run: frida -n FIFA17.exe -l frida_bypass.js
 */
console.log("[*] FIFA 17 ProtoSSL Bypass v5");

var base = Process.enumerateModules()[0].base;
console.log("[*] Base: " + base);

// Known offsets from earlier Frida/DLL analysis:
// +0x6124140 = cert verify function
// +0x6127020 = cert process function  
// +0x61262DC = State 3 (Certificate handler)
// +0x612E7A4 = error handler

var addrs = [
    {name: "cert_verify", off: 0x6124140},
    {name: "cert_process", off: 0x6127020},
    {name: "state3_cert", off: 0x61262DC},
    {name: "error_handler", off: 0x612E7A4},
];

addrs.forEach(function(a) {
    var addr = base.add(a.off);
    console.log("\n[*] " + a.name + " at " + addr + " (exe+" + a.off.toString(16) + "):");
    try {
        var bytes = Memory.readByteArray(addr, 64);
        console.log(hexdump(addr, {length: 64, header: true, ansi: false}));
        
        // Check if it looks like code (not all zeros or 0xCC)
        var view = new Uint8Array(bytes);
        var nonZero = 0;
        for (var i = 0; i < 16; i++) if (view[i] !== 0 && view[i] !== 0xCC) nonZero++;
        if (nonZero < 4) {
            console.log("  [!] Looks like uninitialized/encrypted code");
        } else {
            console.log("  [+] Looks like valid code");
            // Try to disassemble
            try {
                var insns = Instruction.parse(addr);
                console.log("  First instruction: " + insns.mnemonic + " " + insns.opStr);
            } catch(e2) {}
        }
    } catch(e) {
        console.log("  [-] Cannot read: " + e);
    }
});

// Now try to patch cert_verify to return 0
// xor eax, eax (31 C0) + ret (C3) = 3 bytes
var certVerify = base.add(0x6124140);
console.log("\n[*] Attempting to patch cert_verify at " + certVerify);
try {
    var origBytes = Memory.readByteArray(certVerify, 3);
    var orig = new Uint8Array(origBytes);
    console.log("[*] Original bytes: " + orig[0].toString(16) + " " + orig[1].toString(16) + " " + orig[2].toString(16));
    
    // Check if it's valid code
    if (orig[0] === 0 && orig[1] === 0 && orig[2] === 0) {
        console.log("[-] Code not decrypted yet, cannot patch");
    } else {
        Memory.protect(certVerify, 16, 'rwx');
        Memory.writeByteArray(certVerify, [0x31, 0xC0, 0xC3]); // xor eax,eax; ret
        console.log("[+] PATCHED cert_verify: " + orig[0].toString(16) + " " + orig[1].toString(16) + " " + orig[2].toString(16) + " -> 31 C0 C3");
        console.log("[+] Certificate verification is now BYPASSED!");
    }
} catch(e) {
    console.log("[-] Patch failed: " + e);
}

console.log("\n[*] Done. Try connecting now.");
