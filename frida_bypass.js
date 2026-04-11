// v23: Hook send() - when game sends TLS ClientHello, block it and
// set iState=0 on the struct to force plaintext mode
console.log("[*] v23 - block ClientHello, force plaintext");

var ws2 = Process.getModuleByName("ws2_32.dll");
var sendFn = ws2.getExportByName("send");
var base = Process.getModuleByName("FIFA17.exe").base;

// From v22: struct found at 0x27dd0c58 (strHost address)
// Values of 1 found at strHost-232, -196, -160, -124
// strHost-124 = strHost - 0x7C. If iState is at struct+0x8C and strHost at struct+0x100,
// then iState = strHost - 0x74. But we found value=1 at strHost-0x7C (offset +0x84).
// Let's try both.

var patched = false;

Interceptor.attach(sendFn, {
    onEnter: function(args) {
        var buf = args[1];
        var len = args[2].toInt32();
        
        // Detect TLS ClientHello: starts with 16 03 00
        if (len >= 5 && buf.readU8() === 0x16 && buf.add(1).readU8() === 0x03) {
            console.log("[!] TLS ClientHello detected (" + len + " bytes)");
            
            if (!patched) {
                patched = true;
                
                // Find the struct by searching for "winter15.gosredirector.ea.com"
                var pattern = "77 69 6E 74 65 72 31 35 2E 67 6F 73 72 65 64 69 72 65 63 74 6F 72 2E 65 61 2E 63 6F 6D";
                
                Process.enumerateRanges('rw-').forEach(function(range) {
                    if (range.size < 0x200) return;
                    try {
                        Memory.scanSync(range.base, range.size, pattern).forEach(function(match) {
                            var strHost = match.address;
                            
                            // Check for sockaddr at strHost+0x100
                            try {
                                var fam = strHost.add(0x100).readU16();
                                if (fam !== 2) return;
                            } catch(e) { return; }
                            
                            console.log("[+] Struct at " + strHost);
                            
                            // Set ALL candidate iState locations to 0
                            [-232, -196, -160, -124, -116, -108].forEach(function(off) {
                                try {
                                    var val = strHost.add(off).readU32();
                                    if (val >= 1 && val <= 7) {
                                        strHost.add(off).writeU32(0);
                                        console.log("  Set strHost" + off + " from " + val + " to 0");
                                    }
                                } catch(e) {}
                            });
                        });
                    } catch(e) {}
                });
            }
            
            // Block the send by setting length to 0
            args[2] = ptr(0);
            console.log("[!] Blocked ClientHello send");
        }
    }
});

console.log("[*] Ready. Trigger connection.");
