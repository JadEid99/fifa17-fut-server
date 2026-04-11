/**
 * Frida script v10 - Intercept recv and replace the Certificate message
 * with an empty certificate list to skip verification entirely.
 * 
 * Also try: modify the ServerHello to not request a certificate at all
 * by changing the cipher to an anonymous one.
 * 
 * Actually, the simplest approach: modify the state field directly.
 * The SSL state machine checks [rbx+0x8C] for the current state.
 * State 6 = cert processing. If we can advance it past state 6,
 * the game will skip cert verification.
 * 
 * But we don't have the rbx pointer...
 * 
 * New approach: Hook recv and when the game reads the Certificate body,
 * modify it in-place to be an empty cert list (00 00 03 00 00 00).
 * An empty cert list means no certs to verify.
 */

console.log("[*] FIFA 17 SSL Bypass v10 - Recv Interception");

var mainBase = Process.findModuleByName("FIFA17.exe").base;

var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
var closesocketAddr = Module.load("WS2_32.dll").getExportByName("closesocket");
var sslSockets = {};
var recvCount = {};

Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        if (args[1].readU16() === 2) {
            var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
            if (port === 42230) {
                var fd = args[0].toInt32();
                sslSockets[fd] = true;
                recvCount[fd] = 0;
                console.log("[*] connect() to 42230 fd=" + fd);
            }
        }
    }
});

Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            console.log("[SEND len=" + args[2].toInt32() + "]");
        }
    }
});

Interceptor.attach(recvAddr, {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.reqLen = args[2].toInt32();
    },
    onLeave: function(retval) {
        var n = retval.toInt32();
        if (!sslSockets[this.fd] || n <= 0) return;
        
        recvCount[this.fd] = (recvCount[this.fd] || 0) + 1;
        var callNum = recvCount[this.fd];
        
        var data = this.buf.readByteArray(Math.min(n, 64));
        var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
        console.log("[RECV #" + callNum + " len=" + n + "] " + hex);
        
        // The recv pattern is:
        // #1: 5 bytes - ServerHello record header (16 03 03 00 4a)
        // #2: 74 bytes - ServerHello body
        // #3: 5 bytes - Certificate record header (16 03 03 06 2d)
        // #4: 1581 bytes - Certificate body
        // #5: 5 bytes - ServerHelloDone record header (should be 16 03 03 00 04)
        // #6: 4 bytes - ServerHelloDone body (0e 00 00 00)
        
        // On recv #3 (Certificate record header), modify the length to be small
        // so the game reads a tiny cert message instead of the full one
        if (callNum === 3 && n === 5) {
            var bytes = new Uint8Array(this.buf.readByteArray(5));
            if (bytes[0] === 0x16) {
                // Change the record length to 7 (empty cert list: 0b 00 00 03 00 00 00)
                console.log("[*] MODIFYING Certificate record header length from " + ((bytes[3] << 8) | bytes[4]) + " to 7");
                this.buf.add(3).writeU8(0x00);
                this.buf.add(4).writeU8(0x07);
                this.modifiedCertHeader = true;
            }
        }
        
        // On recv #4 (Certificate body), replace with empty cert list
        if (callNum === 4 && this.modifiedCertHeader) {
            // The game will try to read 7 bytes (our modified length)
            // But it actually received 1581 bytes from the server
            // We need to write the empty cert message into the buffer
            // 0b = Certificate handshake type
            // 00 00 03 = length 3
            // 00 00 00 = certificate list length 0 (empty)
            console.log("[*] REPLACING Certificate body with empty cert list!");
            this.buf.writeByteArray([0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]);
            retval.replace(7);
        }
    }
});

Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            console.log("[!] closesocket fd=" + args[0].toInt32());
            console.log("[!] Stack: " + Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 6).map(function(a) {
                return "+" + a.sub(mainBase).toString(16);
            }).join(" -> "));
        }
    }
});

console.log("[*] Ready. Trigger connection!");
