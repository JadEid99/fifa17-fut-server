// Search the ENTIRE exe for CMP [reg+0x8C], value patterns
// to find ProtoSSLSend/Recv which check ST_UNSECURE
console.log("[*] Searching entire exe for iState checks...");
var b = Process.getModuleByName("FIFA17.exe").base;
var size = Process.getModuleByName("FIFA17.exe").size;

// Search in 16MB chunks
var found = 0;
var results = {};
for (var chunk = 0; chunk < size && found < 100; chunk += 0x1000000) {
    var scanSize = Math.min(0x1000000, size - chunk);
    var start = b.add(chunk);
    try {
        for (var i = 0; i < scanSize - 7 && found < 100; i++) {
            // 83 BB 8C 00 00 00 XX = CMP DWORD [rbx+0x8C], XX
            if (start.add(i).readU8() === 0x83 && start.add(i+1).readU8() === 0xBB &&
                start.add(i+2).readU8() === 0x8C && start.add(i+3).readU8() === 0x00 &&
                start.add(i+4).readU8() === 0x00 && start.add(i+5).readU8() === 0x00) {
                var val = start.add(i+6).readU8();
                var addr = chunk + i;
                if (!results[val]) results[val] = [];
                results[val].push("0x" + addr.toString(16));
                found++;
            }
        }
    } catch(e) {}
}

// Print grouped by value
var keys = Object.keys(results).sort(function(a,b){return a-b});
for (var k = 0; k < keys.length; k++) {
    var val = keys[k];
    send("iState==" + val + " checked at: " + results[val].join(", "));
}
send("Total: " + found + " checks found");
