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
// At +0x61262F5: TEST eax, eax (85 C0)
// At +0x61262F7: JLE +0x36 (7E 36) -> jumps to error path
// Change JLE to JMP-never by NOPing it, so we always take success path
// BUT we also need eax > 0 for the success path to work properly
// Replace TEST eax,eax / JLE with MOV eax,1 / NOP NOP
// 85 C0 7E 36 -> B8 01 00 00 (mov eax, 1) which is 5 bytes... too many
// Actually: just NOP the JLE (2 bytes): 7E 36 -> 90 90
try {
    var a = b.add(0x61262F7);
    if (a.readU8() === 0x7E) {
        Memory.protect(a, 2, 'rwx');
        a.writeByteArray([0x90, 0x90]); // NOP the JLE
        console.log("[+] NOP'd JLE at +0x61262F7 (force cert_process success path)");
        patched++;
    }
} catch(e) {}

console.log("[*] Patched " + patched + " locations. Trigger connection now.");
