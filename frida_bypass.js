console.log("[*] v18 - make JNE unconditional to skip error path cleanly");
var base = Process.getModuleByName("FIFA17.exe").base;

// From the disassembly:
// 6126440: 75 21  JNE +0x21 (to 0x6126463) - skip error if condition met
// 6126442: ...    (check bAllowAnyCert or similar)
// 6126449: 75 18  JNE +0x18 (to 0x6126463) - skip error if condition met
// 612644B: ...    (load params)
// 612644E: E8 ... CALL error handler
// 6126453: ...    (set error state)
// 6126463: ...    (continue state machine - check state == 6)
//
// Change 75 21 (JNE) to EB 21 (JMP) = always skip the error path
// This is a 1-byte change: 0x75 -> 0xEB

var jneAddr = base.add(0x6126440);
var b = jneAddr.readU8();
console.log("[*] Byte at exe+0x6126440: 0x" + b.toString(16));

if (b === 0x75) {
    Memory.protect(jneAddr, 1, 'rwx');
    jneAddr.writeU8(0xEB); // JMP (unconditional)
    console.log("[+] Changed JNE to JMP at exe+0x6126440!");
    console.log("[+] Error path is now ALWAYS skipped!");
} else {
    console.log("[-] Expected 0x75 (JNE), got 0x" + b.toString(16));
}

console.log("[*] Trigger connection now.");
