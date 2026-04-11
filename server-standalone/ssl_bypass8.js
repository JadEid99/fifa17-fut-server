/**
 * Frida script v8 - Hook the disconnect function properly and force
 * the SSL state to advance past certificate verification.
 */

console.log("[*] FIFA 17 SSL Bypass v8");

var mainBase = Process.findModuleByName("FIFA17.exe").base;

// Network hooks
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
var closesocketAddr = Module.load("WS2_32.dll").getExportByName("closesocket");
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
        if (sslSockets[args[0].toInt32()]) {
            var len = args[2].toInt32();
            var data = args[1].readByteArray(Math.min(len, 64));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[SEND len=" + len + "] " + hex);
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
            console.log("[RECV len=" + n + "] " + hex);
        }
    }
});

Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            console.log("[!] BLOCKING closesocket fd=" + args[0].toInt32());
            console.log("[!] Stack: " + Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 6).map(function(a) {
                return "+" + a.sub(mainBase).toString(16);
            }).join(" -> "));
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

// Hook the disconnect function at 0x612d5d0
// This is the function called at 0x612e7b8 when cert fails
// Instead of patching it, let's hook it and force return 0
var disconnectFunc = mainBase.add(0x612d5d0);
console.log("[*] Hooking disconnect function at " + disconnectFunc);
console.log("[*] First bytes: " + Array.from(new Uint8Array(disconnectFunc.readByteArray(16))).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));

Interceptor.attach(disconnectFunc, {
    onEnter: function(args) {
        console.log("[DISCONNECT] Called! Forcing early return...");
        console.log("[DISCONNECT] Stack: " + Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 5).map(function(a) {
            return "+" + a.sub(mainBase).toString(16);
        }).join(" -> "));
    },
    onLeave: function(retval) {
        console.log("[DISCONNECT] Return value: " + retval);
        retval.replace(0);
    }
});

// Also hook the function at 0x612e7b8's context
// The code before the call is:
//   40 38 bb 86 03 00 00  = cmp [rbx+0x386], dil
//   74 13                 = je +0x13 (skip the error call if equal)
//   ba 0f a2 ff e7        = mov edx, 0xE7FFA20F
//   8d 92 f3 5d 00 18     = lea edx, [rdx+0x18005DF3]
//   e8 13 ee ff ff        = call disconnect
//   eb 09                 = jmp +9
//
// The je at 0x612e7a9 skips the disconnect call if [rbx+0x386] == dil
// This is the cert verification result check!
// If we NOP the conditional jump to always skip, the disconnect is never called.

// Let's patch the je (74 13) at 0x612e7a9 to jmp (eb 13) - always skip
var jeAddr = mainBase.add(0x612e7a9);
var jeBytes = jeAddr.readByteArray(2);
console.log("[*] Bytes at 0x612e7a9 (conditional jump): " + Array.from(new Uint8Array(jeBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));

Memory.protect(jeAddr, 2, 'rwx');
jeAddr.writeByteArray([0xEB, 0x13]); // Change JE to JMP (always skip error path)
console.log("[+] Patched JE to JMP at 0x612e7a9 - always skip cert error path");

console.log("[*] Ready. Trigger connection now!");
