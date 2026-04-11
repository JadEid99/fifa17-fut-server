// Hook connect() and when game connects to port 42230,
// search for the ProtoSSLRefT struct and set iState=0 (ST_UNSECURE)
console.log("[*] v22 - hook connect, force ST_UNSECURE on port 42230");

var ws2 = Process.getModuleByName("ws2_32.dll");
var connectFn = ws2.getExportByName("connect");
var base = Process.getModuleByName("FIFA17.exe").base;

// We know strHost "winter15.gosredirector.ea.com" is in the struct
// and iState is at struct+0x8C
// strHost is at struct+0x20 (from DirtySDK source)
// So iState is at strHost-0x20+0x8C = strHost+0x6C

// But we don't know the struct address yet. We'll find it by searching
// for the hostname string in writable memory after connect() is called.

Interceptor.attach(connectFn, {
    onEnter: function(args) {
        var sa = args[1];
        if (sa.readU16() === 2) {
            var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            if (port === 42230) {
                console.log("[!] connect() to port 42230 detected!");
                
                // Search writable memory for "winter15.gosredirector.ea.com"
                // and set iState=0 at the right offset
                var pattern = "77 69 6E 74 65 72 31 35 2E 67 6F 73 72 65 64 69 72 65 63 74 6F 72 2E 65 61 2E 63 6F 6D";
                
                Process.enumerateRanges('rw-').forEach(function(range) {
                    if (range.size < 0x200) return;
                    try {
                        Memory.scanSync(range.base, range.size, pattern).forEach(function(match) {
                            // Check if this looks like the struct (has zeros before it)
                            var strHost = match.address;
                            
                            // In the struct, strHost is at +0x20
                            // iState is at +0x8C
                            // So from strHost: iState = strHost - 0x20 + 0x8C = strHost + 0x6C
                            // But the struct layout might differ in FIFA 17.
                            // We know iState is at [rbx+0x8C] and the struct has strHost.
                            // Let's check: at strHost+0x6C, is there a value 1-7?
                            
                            var candidate1 = strHost.add(0x6C).readU32(); // if strHost at +0x20
                            var candidate2 = strHost.add(0xEC).readU32(); // if strHost at +0xA0
                            
                            // Also try: the struct we found in v23 had sockaddr at strHost+0x100
                            // sockaddr has port A4F6 (42230 in network byte order = 0xA4F6)
                            // If sockaddr is at strHost+0x100, and iState is at struct+0x8C,
                            // and strHost is at struct+X, then iState = strHost + (0x8C - X)
                            
                            // Check for sockaddr at strHost+0x100
                            var hasSockAddr = false;
                            try {
                                var fam = strHost.add(0x100).readU16();
                                var ip4 = strHost.add(0x104).readU8();
                                if (fam === 2 && ip4 === 127) hasSockAddr = true;
                            } catch(e) {}
                            
                            if (hasSockAddr) {
                                // This is the real struct! sockaddr at strHost+0x100
                                // means strHost is at a large offset from struct base.
                                // From v23: the struct had pointers at strHost-0x10 and strHost-0x08
                                // Let's find iState by checking values 1-7 in the area
                                console.log("[+] Found struct with sockaddr at " + strHost);
                                
                                for (var off = -0x100; off < 0; off += 4) {
                                    try {
                                        var val = strHost.add(off).readU32();
                                        if (val >= 1 && val <= 7) {
                                            console.log("  [rbx+" + (off+0x100).toString(16) + "]? = " + val + " at strHost" + off);
                                        }
                                    } catch(e) {}
                                }
                                
                                // Try setting the most likely iState locations to 0
                                // From the code, iState is at +0x8C from struct base
                                // If strHost is at struct+0x20, iState = strHost+0x6C
                                // If strHost is at struct+0x100, iState = strHost-0x74
                                console.log("  Setting strHost+0x6C to 0 (if strHost at +0x20)");
                                strHost.add(0x6C).writeU32(0);
                                console.log("  Setting strHost-0x74 to 0 (if strHost at +0x100)");
                                try { strHost.add(-0x74).writeU32(0); } catch(e) {}
                            }
                        });
                    } catch(e) {}
                });
            }
        }
    }
});

console.log("[*] Ready. Trigger connection.");
