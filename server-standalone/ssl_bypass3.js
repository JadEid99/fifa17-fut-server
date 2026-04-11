/**
 * Frida script v3 - Find and patch _VerifyCertificate by scanning for
 * the code pattern that returns -30 (0xFFFFFFE2) on cert failure.
 * 
 * In ProtoSSL, _VerifyCertificate returns -30 when signature hash mismatches.
 * We search for this pattern in the decrypted code and patch it.
 */

console.log("[*] FIFA 17 SSL Bypass v3 - Pattern Scanner");

var mainModule = Process.findModuleByName("FIFA17.exe");
var mainBase = mainModule.base;
var mainSize = mainModule.size;
console.log("[*] FIFA17.exe base=" + mainBase + " size=" + mainSize);

// Hook send/recv to monitor SSL traffic
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
var sslSockets = {};

Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) {
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            if (port === 42230) {
                var fd = args[0].toInt32();
                sslSockets[fd] = true;
                console.log("[*] connect() to port 42230 fd=" + fd);
            }
        }
    }
});

Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (sslSockets[fd]) {
            var len = args[2].toInt32();
            console.log("[SEND fd=" + fd + " len=" + len + "]");
        }
    }
});

Interceptor.attach(recvAddr, {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
    },
    onLeave: function(retval) {
        var bytesRead = retval.toInt32();
        if (sslSockets[this.fd] && bytesRead > 0) {
            console.log("[RECV fd=" + this.fd + " len=" + bytesRead + "]");
        }
    }
});

// Now the key part: scan for the _VerifyCertificate function.
// After receiving the Certificate, ProtoSSL calls _VerifyCertificate.
// If it fails, it returns a negative value (like -30).
// 
// We can find this by searching for the pattern where the function
// sets eax to 0xFFFFFFE2 (-30) which is the "signature hash mismatch" error.
// In x64 assembly: mov eax, 0xFFFFFFE2 = B8 E2 FF FF FF
// Or: mov ecx, 0xFFFFFFE2 then mov eax, ecx

console.log("[*] Scanning for _VerifyCertificate patterns...");

// Pattern: mov eax, -30 (0xFFFFFFE2) = B8 E2 FF FF FF
var pattern1 = "B8 E2 FF FF FF";
var matches = Memory.scanSync(mainBase, mainSize, pattern1);
console.log("[*] Pattern 'mov eax, -30': " + matches.length + " matches");

// Also search for -7 (0xFFFFFFF9) which is another ProtoSSL error
var pattern2 = "B8 F9 FF FF FF";
var matches2 = Memory.scanSync(mainBase, mainSize, pattern2);
console.log("[*] Pattern 'mov eax, -7': " + matches2.length + " matches");

// Search for -6 (0xFFFFFFFA) - "could not get signature algorithm type"
var pattern3 = "B8 FA FF FF FF";
var matches3 = Memory.scanSync(mainBase, mainSize, pattern3);
console.log("[*] Pattern 'mov eax, -6': " + matches3.length + " matches");

// Search for -19 (0xFFFFFFED) - "could not get signature algorithm identifier"
var pattern4 = "B8 ED FF FF FF";
var matches4 = Memory.scanSync(mainBase, mainSize, pattern4);
console.log("[*] Pattern 'mov eax, -19': " + matches4.length + " matches");

// Print first few matches of -30 pattern with context
if (matches.length > 0 && matches.length < 50) {
    for (var i = 0; i < Math.min(matches.length, 20); i++) {
        var addr = matches[i].address;
        // Read surrounding bytes for context
        var before = addr.sub(16).readByteArray(48);
        var hex = Array.from(new Uint8Array(before)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
        console.log("  match " + i + " at " + addr + " (RVA=0x" + addr.sub(mainBase).toString(16) + "): " + hex);
    }
}

// Now let's try a different approach: hook the closesocket call
// and when it's called on our SSL socket, dump the call stack
// to find which function decided to close it
var closesocketAddr = Module.load("WS2_32.dll").getExportByName("closesocket");
Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (sslSockets[fd]) {
            console.log("[!] closesocket(fd=" + fd + ") - SSL socket being closed!");
            console.log("[!] Call stack:");
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(function(addr) {
                var offset = addr.sub(mainBase);
                if (offset.compare(ptr(0)) >= 0 && offset.compare(ptr(mainSize)) < 0) {
                    return "  FIFA17.exe+0x" + offset.toString(16);
                }
                var mod = Process.findModuleByAddress(addr);
                if (mod) return "  " + mod.name + "+0x" + addr.sub(mod.base).toString(16);
                return "  " + addr;
            }).join("\n"));
        }
    }
});

console.log("[*] All hooks installed. Trigger connection now.");
