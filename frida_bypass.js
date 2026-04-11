console.log("[*] v20 - dump State 3 (Certificate) code");
var base = Process.getModuleByName("FIFA17.exe").base;

// State 3 (Certificate processing) is at exe+0x61262DC
// This is where the cert is parsed and verified.
// Dump 256 bytes starting from there.

var state3 = base.add(0x61262DC);
console.log("[*] State 3 (Certificate) at " + state3 + ":");

for (var row = 0; row < 16; row++) {
    var off = row * 16;
    var hex = "";
    for (var i = 0; i < 16; i++) {
        hex += ("0" + state3.add(off + i).readU8().toString(16)).slice(-2) + " ";
    }
    console.log("  +" + (0x61262DC + off).toString(16) + ": " + hex);
}

// Also dump State 4 (ServerHelloDone) at +0x612634D
var state4 = base.add(0x612634D);
console.log("\n[*] State 4 (ServerHelloDone) at " + state4 + ":");
for (var row = 0; row < 8; row++) {
    var off = row * 16;
    var hex = "";
    for (var i = 0; i < 16; i++) {
        hex += ("0" + state4.add(off + i).readU8().toString(16)).slice(-2) + " ";
    }
    console.log("  +" + (0x612634D + off).toString(16) + ": " + hex);
}

// Look for CALL instructions in State 3 that might be cert verify
var addr = state3;
for (var i = 0; i < 128; i++) {
    if (addr.add(i).readU8() === 0xE8) {
        var disp = addr.add(i+1).readS32();
        var target = addr.add(i+5).add(disp);
        var targetOff = target.sub(base);
        console.log("\n[*] CALL at exe+" + addr.add(i).sub(base) + " -> exe+" + targetOff);
    }
}

console.log("\n[*] Done.");
