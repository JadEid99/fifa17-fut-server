/**
 * Frida script v11 - Intercept the bad_certificate alert the game sends
 * and replace it with a ClientKeyExchange.
 * 
 * When the game sends alert 0x2a (bad_certificate), we suppress it
 * and instead let the connection continue.
 */

console.log("[*] FIFA 17 SSL Bypass v11 - Alert Suppression");

var mainBase = Process.findModuleByName("FIFA17.exe").base;

var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
var closesocketAddr = Module.load("WS2_32.dll").getExportByName("closesocket");
var sslSockets = {};

Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        if (args[1].readU16() === 2) {
            var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
            if (port === 42230) {
                sslSockets[args[0].toInt32()] = true;
                console.log("[*] connect() to 42230 fd=" + args[0].toInt32());
            }
        }
    }
});

// Intercept send and BLOCK TLS alerts
Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (!sslSockets[fd]) return;
        
        var len = args[2].toInt32();
        var buf = args[1];
        var firstByte = buf.readU8();
        
        if (firstByte === 0x15 && len === 7) {
            // This is a TLS Alert record
            var alertLevel = buf.add(5).readU8();
            var alertDesc = buf.add(6).readU8();
            console.log("[!] BLOCKING TLS Alert: level=" + alertLevel + " desc=" + alertDesc + " (0x" + alertDesc.toString(16) + ")");
            // Replace with a NOP - set length to 0 so nothing is sent
            args[2] = ptr(0);
            this.blocked = true;
        } else {
            var data = buf.readByteArray(Math.min(len, 64));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[SEND fd=" + fd + " len=" + len + "] " + hex);
        }
    },
    onLeave: function(retval) {
        if (this.blocked) {
            // Make it look like the send succeeded
            retval.replace(7);
            this.blocked = false;
        }
    }
});

Interceptor.attach(recvAddr, {
    onEnter: function(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
    onLeave: function(retval) {
        var n = retval.toInt32();
        if (sslSockets[this.fd] && n > 0) {
            var data = this.buf.readByteArray(Math.min(n, 64));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[RECV fd=" + this.fd + " len=" + n + "] " + hex);
        }
    }
});

Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            console.log("[!] BLOCKING closesocket fd=" + args[0].toInt32());
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

// Also patch the JE->JMP
var jeAddr = mainBase.add(0x612e7a9);
Memory.protect(jeAddr, 2, 'rwx');
jeAddr.writeByteArray([0xEB, 0x13]);
console.log("[+] Patched JE->JMP at 0x612e7a9");

console.log("[*] Ready. Trigger connection!");
