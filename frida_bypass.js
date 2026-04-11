console.log("[*] v15 - PATCH cert verification");
var base = Process.getModuleByName("FIFA17.exe").base;

// From the stack trace, exe+0x6126453 is where the SSL state machine
// decides to disconnect after cert failure. Let's look at what's there.

// The state machine address 0x6126453 is between State 5 (+0x6126416) 
// and State 6 (+0x6126463). This is likely a CALL to the error handler
// or a conditional jump.

// Let's dump the code and find the conditional branch we need to patch.
var addr = base.add(0x6126440);
console.log("[*] Dumping code at exe+0x6126440 (around the failure point):");
for (var off = 0; off < 48; off++) {
    // nothing, just read
}
var hex = "";
for (var i = 0; i < 48; i++) {
    hex += ("0" + addr.add(i).readU8().toString(16)).slice(-2) + " ";
    if ((i+1) % 16 === 0) {
        console.log("  +" + (0x6126440 + i - 15).toString(16) + ": " + hex);
        hex = "";
    }
}

// Now let's try the simplest approach: patch the error handler at exe+0x612E7A4
// (the address from NEXT_SESSION_PLAN) to return immediately without disconnecting.
// The stack shows exe+0x612E7C5 as return address, meaning the CALL to disconnect
// is at approximately exe+0x612E7C0.

// Let's dump around exe+0x612E7B0 to find the CALL instruction
addr = base.add(0x612E7B0);
console.log("\n[*] Code around the CALL to disconnect (exe+0x612E7B0):");
hex = "";
for (var i = 0; i < 32; i++) {
    hex += ("0" + addr.add(i).readU8().toString(16)).slice(-2) + " ";
    if ((i+1) % 16 === 0) {
        console.log("  +" + (0x612E7B0 + i - 15).toString(16) + ": " + hex);
        hex = "";
    }
}

// The CALL to disconnect at exe+0x612D730 from exe+0x612E7C0 would be:
// E8 xx xx xx xx where xx = 0x612D730 - 0x612E7C5 = -0x1095 = FFFFF6B
// Let's check: E8 6B EF FF FF
// If we find E8 followed by a displacement that points to 0x612D730, we NOP it

// Actually, let's just NOP the call. Find E8 near exe+0x612E7C0
for (var scan = -10; scan <= 0; scan++) {
    var scanAddr = base.add(0x612E7C5 + scan);
    if (scanAddr.readU8() === 0xE8) {
        var disp = scanAddr.add(1).readS32();
        var target = scanAddr.add(5).add(disp);
        var targetOff = target.sub(base);
        console.log("\n[*] Found CALL at exe+" + scanAddr.sub(base) + " -> exe+" + targetOff);
        
        if (targetOff.toInt32() >= 0x612D000 && targetOff.toInt32() <= 0x612E000) {
            console.log("[+] This calls the disconnect function! NOP-ing it...");
            Memory.protect(scanAddr, 5, 'rwx');
            // NOP the 5-byte CALL: 90 90 90 90 90
            scanAddr.writeU8(0x90);
            scanAddr.add(1).writeU8(0x90);
            scanAddr.add(2).writeU8(0x90);
            scanAddr.add(3).writeU8(0x90);
            scanAddr.add(4).writeU8(0x90);
            console.log("[+] PATCHED! Disconnect call NOP'd!");
        }
    }
}

console.log("\n[*] Done. Trigger connection now.");
