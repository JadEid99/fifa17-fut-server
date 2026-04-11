/**
 * Frida script v5 - NOP out the SSL disconnect call and force the handshake to continue.
 * 
 * From our analysis:
 * - 0x612e7c0: CALL to disconnect function (e8 7b d3 ff ff)
 * - 0x612d650: The disconnect function itself
 * - 0x6126453: SSL state machine
 * 
 * We NOP the call at 0x612e7c0 so the disconnect never happens,
 * AND we hook closesocket/shutdown to block any socket closure on SSL sockets.
 */

console.log("[*] FIFA 17 SSL Bypass v5 - Direct Patch");

var mainBase = Process.findModuleByName("FIFA17.exe").base;
var mainSize = Process.findModuleByName("FIFA17.exe").size;

// Patch the CALL at 0x612e7c0 (e8 7b d3 ff ff) to NOPs (90 90 90 90 90)
var callAddr = mainBase.add(0x612e7c0);
var origBytes = callAddr.readByteArray(5);
console.log("[*] Original bytes at 0x612e7c0: " + Array.from(new Uint8Array(origBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));

Memory.protect(callAddr, 5, 'rwx');
callAddr.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
console.log("[+] Patched CALL at 0x612e7c0 to NOP (5 bytes)");

// Also read and dump the code around the SSL state machine for analysis
var sslState = mainBase.add(0x6126453);
var codeDump = sslState.sub(64).readByteArray(192);
var hex = Array.from(new Uint8Array(codeDump));
console.log("[*] Code around SSL state machine (0x6126453):");
for (var row = 0; row < 192; row += 16) {
    var line = "";
    for (var col = 0; col < 16 && row + col < 192; col++) {
        if (row + col === 64) line += "[";
        line += ('0' + hex[row + col].toString(16)).slice(-2) + " ";
        if (row + col === 64) line += "] ";
    }
    var rva = 0x6126453 - 64 + row;
    console.log("  +" + rva.toString(16) + ": " + line);
}

// Network hooks
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
var closesocketAddr = Module.load("WS2_32.dll").getExportByName("closesocket");
var shutdownAddr = Module.load("WS2_32.dll").getExportByName("shutdown");
var sslSockets = {};

Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        var sockaddr = args[1];
        if (sockaddr.readU16() === 2) {
            var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
            if (port === 42230) {
                sslSockets[args[0].toInt32()] = true;
                console.log("[*] connect() to 42230 fd=" + args[0].toInt32());
            }
        }
    }
});

Interceptor.attach(sendAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (sslSockets[fd]) {
            var len = args[2].toInt32();
            var data = args[1].readByteArray(Math.min(len, 64));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[SEND fd=" + fd + " len=" + len + "] " + hex);
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

// Block closesocket on SSL sockets
Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (sslSockets[fd]) {
            console.log("[!] BLOCKING closesocket(fd=" + fd + ")");
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

// Block shutdown on SSL sockets
Interceptor.attach(shutdownAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (sslSockets[fd]) {
            console.log("[!] BLOCKING shutdown(fd=" + fd + ")");
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

console.log("[*] All patches and hooks applied. Trigger connection now.");
