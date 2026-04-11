/**
 * Frida v3 - Only scan main exe module (faster), search for key strings.
 * Run: frida -n FIFA17.exe -l frida_bypass.js
 */
console.log("[*] FIFA 17 ProtoSSL Bypass v3");

var mod = Process.enumerateModules()[0];
console.log("[*] " + mod.name + " base=" + mod.base + " size=" + mod.size);

// We know "installed CA cert" is at exe+0x39316B1
// Search only within the exe module for other strings
var searches = [
    {name: "installed CA cert", hex: "69 6E 73 74 61 6C 6C 65 64 20 43 41 20 63 65 72 74"},
    {name: "cert untrusted", hex: "63 65 72 74 20 75 6E 74 72 75 73 74 65 64"},
    {name: "cert invalid", hex: "63 65 72 74 20 69 6E 76 61 6C 69 64"},
    {name: "no CA available", hex: "6E 6F 20 43 41 20 61 76 61 69 6C 61 62 6C 65"},
    {name: "signature hash", hex: "73 69 67 6E 61 74 75 72 65 20 68 61 73 68"},
    {name: "SetCACert", hex: "53 65 74 43 41 43 65 72 74"},
    {name: "protossl:", hex: "70 72 6F 74 6F 73 73 6C 3A"},
    {name: "_ServerCert:", hex: "5F 53 65 72 76 65 72 43 65 72 74"},
    {name: "ncrt", hex: "6E 63 72 74"},
    {name: "Process Server Cert", hex: "50 72 6F 63 65 73 73 20 53 65 72 76 65 72 20 43 65 72 74"},
];

// Scan in 16MB chunks to avoid timeout
var base = mod.base;
var remaining = mod.size;
var chunkSize = 16 * 1024 * 1024;

searches.forEach(function(s) {
    var found = [];
    var off = 0;
    while (off < mod.size && found.length < 3) {
        var scanSize = Math.min(chunkSize, mod.size - off);
        try {
            Memory.scanSync(base.add(off), scanSize, s.hex).forEach(function(m) {
                found.push(m.address);
            });
        } catch(e) {}
        off += chunkSize;
    }
    if (found.length > 0) {
        found.forEach(function(a) {
            console.log("[+] '" + s.name + "' at " + a + " (exe+" + a.sub(base) + ")");
        });
    } else {
        console.log("[-] '" + s.name + "' NOT FOUND");
    }
});

console.log("\n[*] Done.");
