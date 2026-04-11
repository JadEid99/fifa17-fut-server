/**
 * Patch the dumped exe to bypass ALL bAllowAnyCert checks.
 * Then we can use Frida to write the patched bytes back to memory.
 * 
 * The bAllowAnyCert check pattern is:
 *   80 BB 20 0C 00 00 00  CMP BYTE [rbx+0xC20], 0
 *   75 18                  JNE +0x18 (skip error if bAllowAnyCert != 0)
 * 
 * We change the JNE (75) to JMP (EB) so it ALWAYS skips the error.
 * This is at byte offset +7 in the 9-byte pattern (the 75 byte).
 * 
 * Found at 3 locations:
 *   0x6125226, 0x6127536, 0x6127C22
 * 
 * We also need to handle the State 5 error CALL at 0x612644E.
 */
const fs = require('fs');

// The 3 bAllowAnyCert check locations
const checks = [0x6125226, 0x6127536, 0x6127C22];

// The State 5 error CALL
const errorCall = 0x612644E;

console.log("=== FIFA 17 SSL Bypass Patcher ===\n");

// Generate a Frida script that patches all locations in memory
let fridaScript = `// Auto-generated: patch ALL bAllowAnyCert checks + error CALL
console.log("[*] Patching ALL SSL checks...");
var b = Process.getModuleByName("FIFA17.exe").base;
var patched = 0;

`;

for (const addr of checks) {
    // The JNE byte is at offset +7 from the pattern start
    const jneAddr = addr + 7;
    fridaScript += `// bAllowAnyCert check at +0x${addr.toString(16)}: change JNE (75) to JMP (EB)
try {
    var a = b.add(0x${jneAddr.toString(16)});
    var old = a.readU8();
    if (old === 0x75) {
        Memory.protect(a, 1, 'rwx');
        a.writeU8(0xEB);
        console.log("[+] Patched +0x${jneAddr.toString(16)}: 0x" + old.toString(16) + " -> 0xEB");
        patched++;
    } else {
        console.log("[-] +0x${jneAddr.toString(16)}: expected 0x75, got 0x" + old.toString(16));
    }
} catch(e) { console.log("[-] Error at +0x${jneAddr.toString(16)}: " + e.message); }

`;
}

// NOP the State 5 error CALL
fridaScript += `// NOP State 5 error CALL at +0x${errorCall.toString(16)}
try {
    var a = b.add(0x${errorCall.toString(16)});
    Memory.protect(a, 5, 'rwx');
    a.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] NOP'd error CALL at +0x${errorCall.toString(16)}");
    patched++;
} catch(e) { console.log("[-] Error: " + e.message); }

console.log("[*] Patched " + patched + " locations. Trigger connection now.");
`;

// Write the Frida script
fs.writeFileSync('frida_patch_all.js', fridaScript);
console.log("Generated frida_patch_all.js");
console.log("\nPatches:");
for (const addr of checks) {
    console.log(`  bAllowAnyCert JNE->JMP at +0x${(addr+7).toString(16)}`);
}
console.log(`  NOP error CALL at +0x${errorCall.toString(16)}`);
console.log("\nUsage:");
console.log("  1. Launch FIFA 17, wait 20s");
console.log("  2. frida -n FIFA17.exe -l frida_patch_all.js");
console.log("  3. Press Q to trigger connection");
