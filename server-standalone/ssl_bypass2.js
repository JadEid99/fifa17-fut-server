/**
 * Frida script v2 - Scan memory for ProtoSSL _VerifyCertificate and patch it.
 * 
 * Instead of hooking memcmp, we search for the function that references
 * the "bad certificate" string and patch it to always return 0.
 * 
 * We also try hooking the send() syscall to see what the game sends
 * during the SSL handshake.
 */

console.log("[*] FIFA 17 SSL Bypass v2");

var mainModule = Process.findModuleByName("FIFA17.exe");
var mainBase = mainModule.base;
var mainSize = mainModule.size;
console.log("[*] FIFA17.exe base=" + mainBase + " size=" + mainSize);

// Strategy: Find the "bad certificate" string in memory, then search
// for code that loads its address. In x64, this is typically done with
// LEA reg, [rip+offset]. But Denuvo obfuscates these references.
//
// Alternative: Hook the SSL alert sending. When ProtoSSL rejects a cert,
// it sends a TLS alert (0x15). We can hook the send/WSASend function
// and intercept the alert, or better yet, hook the function that
// constructs the alert.
//
// Best approach: Hook WSASend/send to see ALL data the game sends on
// the socket, and also hook the connect() to know when it connects.

// Hook send() from WS2_32.dll
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
var WSASendAddr = Module.load("WS2_32.dll").getExportByName("WSASend");

console.log("[*] send=" + sendAddr + " connect=" + connectAddr + " WSASend=" + WSASendAddr);

// Track which sockets connect to port 42230
var sslSockets = {};

Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            var ip = sockaddr.add(4).readU8() + "." + sockaddr.add(5).readU8() + "." + sockaddr.add(6).readU8() + "." + sockaddr.add(7).readU8();
            if (port === 42230) {
                var fd = args[0].toInt32();
                sslSockets[fd] = true;
                console.log("[*] connect() to " + ip + ":" + port + " fd=" + fd);
            }
        }
    }
});

Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (sslSockets[fd]) {
            var buf = args[1];
            var len = args[2].toInt32();
            var data = buf.readByteArray(Math.min(len, 256));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[SEND fd=" + fd + " len=" + len + "] " + hex);
        }
    }
});

// Also hook recv to see what the game receives back
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
Interceptor.attach(recvAddr, {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        var bytesRead = retval.toInt32();
        if (sslSockets[this.fd] && bytesRead > 0) {
            var data = this.buf.readByteArray(Math.min(bytesRead, 256));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[RECV fd=" + this.fd + " len=" + bytesRead + "] " + hex);
            
            // Check if this is a TLS alert (0x15)
            var bytes = new Uint8Array(data);
            if (bytes[0] === 0x15) {
                console.log("[!] TLS ALERT received by game! level=" + bytes[5] + " desc=" + bytes[6]);
            }
            
            // Check if this is a ServerHello (0x16 ... 0x02)
            if (bytes[0] === 0x16) {
                console.log("[*] TLS Handshake record received by game, first HS byte: 0x" + bytes[5].toString(16));
            }
        }
    }
});

console.log("[*] Hooks installed. Start SSL proxy + Node server, then trigger connection.");
console.log("[*] This will show ALL SSL traffic the game sends/receives.");
