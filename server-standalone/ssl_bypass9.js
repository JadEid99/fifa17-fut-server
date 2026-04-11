/**
 * Frida script v9 - Patch the conditional jump and block closesocket.
 * The function at 0x612d5d0 is already patched to return 0 from a previous session.
 */

console.log("[*] FIFA 17 SSL Bypass v9");

var mainBase = Process.findModuleByName("FIFA17.exe").base;

// Patch JE to JMP at 0x612e7a9 - always skip cert error path
var jeAddr = mainBase.add(0x612e7a9);
Memory.protect(jeAddr, 2, 'rwx');
jeAddr.writeByteArray([0xEB, 0x13]);
console.log("[+] Patched JE->JMP at 0x612e7a9");

// Network hooks
var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
var closesocketAddr = Module.load("WS2_32.dll").getExportByName("closesocket");
var sslSockets = {};

Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        if (args[1].readU16() === 2) {
            var port = (args[1].add(2).readU8() << 8) | args[1].add(3).readU8();
            if (port === 42230 || port === 10041) {
                sslSockets[args[0].toInt32()] = true;
                console.log("[*] connect() to port " + port + " fd=" + args[0].toInt32());
            }
        }
    }
});

Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            var len = args[2].toInt32();
            var data = args[1].readByteArray(Math.min(len, 64));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[SEND fd=" + args[0].toInt32() + " len=" + len + "] " + hex);
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
            console.log("[!] closesocket fd=" + args[0].toInt32());
            console.log("[!] Stack: " + Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 6).map(function(a) {
                return "+" + a.sub(mainBase).toString(16);
            }).join(" -> "));
        }
    }
});

console.log("[*] Ready. Trigger connection!");
