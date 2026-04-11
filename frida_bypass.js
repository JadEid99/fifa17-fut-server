/**
 * Frida script v2 - search for known strings we've confirmed exist.
 * 
 * From v7 DLL logs: "installed CA cert" was found at 0x1439316B1
 * That's exe_base + 0x39316B1
 * 
 * Run: frida -n FIFA17.exe -l frida_bypass.js
 */

console.log("[*] FIFA 17 ProtoSSL Bypass v2");

var mod = Process.enumerateModules()[0];
console.log("[*] Main module: " + mod.name + " base=" + mod.base + " size=" + mod.size);

// Search for strings we KNOW exist from DLL logs
var searches = [
    {name: "installed CA cert", hex: "69 6E 73 74 61 6C 6C 65 64 20 43 41 20 63 65 72 74"},
    {name: "cert untrusted", hex: "63 65 72 74 20 75 6E 74 72 75 73 74 65 64"},
    {name: "cert invalid", hex: "63 65 72 74 20 69 6E 76 61 6C 69 64"},
    {name: "no CA available", hex: "6E 6F 20 43 41 20 61 76 61 69 6C 61 62 6C 65"},
    {name: "signature hash", hex: "73 69 67 6E 61 74 75 72 65 20 68 61 73 68"},
    {name: "VerifyCert", hex: "56 65 72 69 66 79 43 65 72 74"},
    {name: "SetCACert", hex: "53 65 74 43 41 43 65 72 74"},
    {name: "AllowAnyCert", hex: "41 6C 6C 6F 77 41 6E 79 43 65 72 74"},
    {name: "bAllowAnyCert", hex: "62 41 6C 6C 6F 77 41 6E 79"},
    {name: "ncrt", hex: "6E 63 72 74"},
    {name: "protossl:", hex: "70 72 6F 74 6F 73 73 6C 3A"},
    {name: "_ServerCert:", hex: "5F 53 65 72 76 65 72 43 65 72 74 3A"},
];

searches.forEach(function(s) {
    var found = [];
    Process.enumerateRanges('r--').forEach(function(range) {
        if (found.length >= 3) return;
        try {
            Memory.scanSync(range.base, range.size, s.hex).forEach(function(match) {
                found.push({addr: match.address, prot: range.protection});
            });
        } catch(e) {}
    });
    if (found.length > 0) {
        found.forEach(function(f) {
            var offset = f.addr.sub(mod.base);
            console.log("[+] '" + s.name + "' at " + f.addr + " (exe+" + offset + ") prot=" + f.prot);
        });
    } else {
        console.log("[-] '" + s.name + "' NOT FOUND");
    }
});

console.log("\n[*] Done.");
