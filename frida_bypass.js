/**
 * Frida v8 - Hook Winsock send() to catch the SSL alert being sent,
 * then trace the call stack to find the cert verification function.
 * 
 * When the game rejects our cert, it sends: 15 03 00 00 02 02 2A
 * (SSL Alert, fatal, bad_certificate)
 * 
 * By hooking send() and checking for this pattern, we can get a
 * stack trace that leads us to the cert verification code.
 * 
 * Run: frida -n FIFA17.exe -l frida_bypass.js
 * Then trigger a connection.
 */
console.log("[*] FIFA 17 ProtoSSL Bypass v8 - trace SSL alert");

// Hook Winsock send()
var ws2 = Module.findBaseAddress("ws2_32.dll");
if (!ws2) {
    ws2 = Module.findBaseAddress("WS2_32.dll");
}
if (!ws2) {
    ws2 = Module.findBaseAddress("WS2_32.DLL");
}

var sendAddr = Module.findExportByName("ws2_32.dll", "send");
var connectAddr = Module.findExportByName("ws2_32.dll", "connect");

if (sendAddr) {
    console.log("[+] send() at " + sendAddr);
    
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            this.socket = args[0];
            this.buf = args[1];
            this.len = args[2].toInt32();
            
            // Check if this is an SSL alert (starts with 0x15)
            if (this.len >= 7) {
                var b0 = this.buf.readU8();
                if (b0 === 0x15) { // SSL Alert
                    var bytes = [];
                    for (var i = 0; i < Math.min(this.len, 16); i++) {
                        bytes.push(this.buf.add(i).readU8().toString(16).padStart(2, '0'));
                    }
                    console.log("\n[!] SSL ALERT sent! " + bytes.join(' '));
                    console.log("[!] Stack trace:");
                    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n'));
                }
            }
            
            // Also log all sends to port 42230
            if (this.len > 0 && this.len < 2000) {
                var b0 = this.buf.readU8();
                // Log TLS records (type 0x14-0x17 or 0x15)
                if (b0 >= 0x14 && b0 <= 0x17) {
                    var bytes = [];
                    for (var i = 0; i < Math.min(this.len, 8); i++) {
                        bytes.push(this.buf.add(i).readU8().toString(16).padStart(2, '0'));
                    }
                    console.log("[send] TLS record: " + bytes.join(' ') + " (" + this.len + " bytes)");
                }
            }
        }
    });
} else {
    console.log("[-] send() not found");
}

if (connectAddr) {
    console.log("[+] connect() at " + connectAddr);
    
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            var sockaddr = args[1];
            var family = sockaddr.readU16();
            if (family === 2) { // AF_INET
                var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                var ip = sockaddr.add(4).readU8() + "." + sockaddr.add(5).readU8() + "." + 
                         sockaddr.add(6).readU8() + "." + sockaddr.add(7).readU8();
                console.log("[connect] " + ip + ":" + port);
            }
        }
    });
} else {
    console.log("[-] connect() not found");
}

console.log("[*] Hooks installed. Trigger a connection now.");
