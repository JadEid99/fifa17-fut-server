// Auto-generated: patch ALL bAllowAnyCert checks + error CALL
console.log("[*] Patching ALL SSL checks...");
var b = Process.getModuleByName("FIFA17.exe").base;
var patched = 0;

// bAllowAnyCert check at +0x6125226: change JNE (75) to JMP (EB)
try {
    var a = b.add(0x612522d);
    var old = a.readU8();
    if (old === 0x75) {
        Memory.protect(a, 1, 'rwx');
        a.writeU8(0xEB);
        console.log("[+] Patched +0x612522d: 0x" + old.toString(16) + " -> 0xEB");
        patched++;
    } else {
        console.log("[-] +0x612522d: expected 0x75, got 0x" + old.toString(16));
    }
} catch(e) { console.log("[-] Error at +0x612522d: " + e.message); }

// bAllowAnyCert check at +0x6127536: change JNE (75) to JMP (EB)
try {
    var a = b.add(0x612753d);
    var old = a.readU8();
    if (old === 0x75) {
        Memory.protect(a, 1, 'rwx');
        a.writeU8(0xEB);
        console.log("[+] Patched +0x612753d: 0x" + old.toString(16) + " -> 0xEB");
        patched++;
    } else {
        console.log("[-] +0x612753d: expected 0x75, got 0x" + old.toString(16));
    }
} catch(e) { console.log("[-] Error at +0x612753d: " + e.message); }

// bAllowAnyCert check at +0x6127c22: change JNE (75) to JMP (EB)
try {
    var a = b.add(0x6127c29);
    var old = a.readU8();
    if (old === 0x75) {
        Memory.protect(a, 1, 'rwx');
        a.writeU8(0xEB);
        console.log("[+] Patched +0x6127c29: 0x" + old.toString(16) + " -> 0xEB");
        patched++;
    } else {
        console.log("[-] +0x6127c29: expected 0x75, got 0x" + old.toString(16));
    }
} catch(e) { console.log("[-] Error at +0x6127c29: " + e.message); }

// NOP State 5 error CALL at +0x612644e
try {
    var a = b.add(0x612644e);
    Memory.protect(a, 5, 'rwx');
    a.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] NOP'd error CALL at +0x612644e");
    patched++;
} catch(e) { console.log("[-] Error: " + e.message); }

console.log("[*] Patched " + patched + " locations. Trigger connection now.");
