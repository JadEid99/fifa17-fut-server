// FINAL BYPASS: Set the REAL bAllowAnyCert at offset 0x384
// Found via Ghidra: *(char*)(param_1 + 900) != '\0' skips ALL verification
// 900 decimal = 0x384 hex
// param_1 is the ProtoSSL connection struct
// We find it by searching for "winter15.gosredirector.ea.com" and calculating offset

console.log("[*] Setting REAL bAllowAnyCert at offset 0x384");
var b = Process.getModuleByName("FIFA17.exe").base;

// Also search the dump for the byte pattern that checks 0x384
// In x64: 80 B9 84 03 00 00 00 (CMP BYTE [rcx+0x384], 0)
// or: 80 BB 84 03 00 00 00 (CMP BYTE [rbx+0x384], 0)
// or: 38 .. 84 03 00 00 (CMP [reg+0x384], reg)

// Search for pattern in executable memory
var patterns = [
    "80 B9 84 03 00 00",  // CMP BYTE [rcx+0x384], ...
    "80 BB 84 03 00 00",  // CMP BYTE [rbx+0x384], ...
    "80 B8 84 03 00 00",  // CMP BYTE [rax+0x384], ...
    "80 BE 84 03 00 00",  // CMP BYTE [rsi+0x384], ...
    "80 BF 84 03 00 00",  // CMP BYTE [rdi+0x384], ...
];

var mod = Process.getModuleByName("FIFA17.exe");
patterns.forEach(function(pat) {
    try {
        var matches = Memory.scanSync(mod.base, mod.size, pat);
        matches.forEach(function(m) {
            send("Pattern " + pat + " at " + m.address + " (exe+" + m.address.sub(mod.base) + ")");
        });
    } catch(e) {}
});

send("Done searching");
