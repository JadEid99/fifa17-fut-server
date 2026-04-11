console.log("[*] v16 - NOP disconnect call at exe+0x612E7B8");
var base = Process.getModuleByName("FIFA17.exe").base;

// From v15 output:
// exe+0x612E7B8: E8 13 EE FF FF -> calls exe+0x612D5D0 (disconnect!)
// Verify and NOP it

var callAddr = base.add(0x612E7B8);
var b = callAddr.readU8();
console.log("[*] Byte at exe+0x612E7B8: 0x" + b.toString(16));

if (b === 0xE8) {
    var disp = callAddr.add(1).readS32();
    var target = callAddr.add(5).add(disp);
    console.log("[*] CALL target: " + target + " (exe+" + target.sub(base) + ")");
    
    Memory.protect(callAddr, 5, 'rwx');
    callAddr.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] NOP'd the disconnect CALL at exe+0x612E7B8!");
} else {
    console.log("[-] Expected E8 (CALL), got 0x" + b.toString(16));
}

console.log("[*] Trigger connection now.");
