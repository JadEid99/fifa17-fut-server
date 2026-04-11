// Patch ALL bAllowAnyCert checks + force cert_process success branch
console.log("[*] Patching ALL SSL checks + forcing cert_process success...");
var b = Process.getModuleByName("FIFA17.exe").base;
var patched = 0;

// Patch 3 bAllowAnyCert JNE -> JMP
[0x612522d, 0x612753d, 0x6127c29].forEach(function(off) {
    try {
        var a = b.add(off);
        if (a.readU8() === 0x75) {
            Memory.protect(a, 1, 'rwx');
            a.writeU8(0xEB);
            console.log("[+] bAllowAnyCert JNE->JMP at +0x" + off.toString(16));
            patched++;
        }
    } catch(e) { console.log("[-] " + e.message); }
});

// NOP State 5 error CALL
try {
    var a = b.add(0x612644e);
    Memory.protect(a, 5, 'rwx');
    a.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] NOP'd error CALL at +0x612644e");
    patched++;
} catch(e) {}

// CRITICAL: Force cert_process success branch
// At +0x61262F5: TEST eax, eax (85 C0) - 2 bytes
// At +0x61262F7: JLE +0x36 (7E 36) - 2 bytes  
// Total: 4 bytes. Replace with: MOV eax, 1 (B8 01 00 00 00) - 5 bytes
// We need 5 bytes but only have 4. So use: XOR eax,eax; INC eax; NOP
// 31 C0 = xor eax,eax (2 bytes)
// FF C0 = inc eax (2 bytes) -> eax = 1
// That's exactly 4 bytes!
try {
    var a = b.add(0x61262F5);
    Memory.protect(a, 4, 'rwx');
    a.writeByteArray([0x31, 0xC0, 0xFF, 0xC0]); // xor eax,eax; inc eax -> eax=1
    console.log("[+] Forced eax=1 at +0x61262F5 (cert_process always succeeds)");
    patched++;
} catch(e) {}

console.log("[*] Patched " + patched + " locations. Trigger connection now.");
