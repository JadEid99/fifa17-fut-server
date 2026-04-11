console.log("[*] Fast scan for iState checks");
var m = Process.getModuleByName("FIFA17.exe");

// Search for: 83 BB 8C 00 00 00 XX (CMP DWORD [rbx+0x8C], XX)
// Use Memory.scanSync with wildcard for the value byte
// Scan in chunks since the exe is huge

var results = {};
var chunkSize = 16 * 1024 * 1024;
for (var off = 0; off < m.size; off += chunkSize) {
    var sz = Math.min(chunkSize, m.size - off);
    try {
        // Pattern: 83 BB 8C 00 00 00 ?? (7 bytes, last is wildcard)
        var matches = Memory.scanSync(m.base.add(off), sz, "83 BB 8C 00 00 00");
        matches.forEach(function(match) {
            var val = match.address.add(6).readU8();
            var addr = match.address.sub(m.base);
            if (!results[val]) results[val] = [];
            results[val].push(addr.toString());
        });
    } catch(e) {}
}

var keys = Object.keys(results).sort(function(a,b){return parseInt(a)-parseInt(b)});
keys.forEach(function(val) {
    send("iState==" + val + " (" + results[val].length + "x): " + results[val].slice(0,5).join(", "));
});
send("Done");
