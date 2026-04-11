/**
 * Frida script v6 - Patch the certificate verification function.
 * 
 * From the code at 0x612e7b8:
 *   e8 13 ee ff ff    = CALL 0x612b5d0  (this is likely _VerifyCertificate or _ParseCertificate)
 *   eb 09             = JMP +9 (skip error handling if call succeeded?)
 *   bc                = ... (error path)
 *   e8 7b d3 ff ff    = CALL disconnect (we already NOP'd this)
 * 
 * The function at 0x612b5d0 is the cert verification. We need to make it return 0.
 * 
 * Let's hook it and force return 0, or patch its first bytes to:
 *   xor eax, eax   (31 C0)
 *   ret            (C3)
 */

console.log("[*] FIFA 17 SSL Bypass v6 - Cert Verification Patch");

var mainBase = Process.findModuleByName("FIFA17.exe").base;

// First, let's verify the call target
// At 0x612e7b8: e8 13 ee ff ff
// CALL target = 0x612e7b8 + 5 + 0xFFFFEE13 = 0x612e7bd + (-0x11ED) = 0x612b5d0
// Wait, let me recalculate: 0x612e7b8 + 5 + signed(0xFFFFEE13)
// 0xFFFFEE13 as signed 32-bit = -0x11ED
// 0x612e7BD - 0x11ED = 0x612D5D0... hmm let me read the actual bytes

var callSite = mainBase.add(0x612e7b8);
var callBytes = callSite.readByteArray(16);
var hex = Array.from(new Uint8Array(callBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
console.log("[*] Bytes at 0x612e7b8: " + hex);

// Read the call offset (little-endian signed 32-bit at offset 1)
var callOffset = callSite.add(1).readS32();
var callTarget = callSite.add(5).add(callOffset);
console.log("[*] CALL at 0x612e7b8 -> target: " + callTarget + " (offset=" + callOffset + ", RVA=0x" + callTarget.sub(mainBase).toString(16) + ")");

// Read the first bytes of the target function
var targetBytes = callTarget.readByteArray(32);
hex = Array.from(new Uint8Array(targetBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
console.log("[*] Target function bytes: " + hex);

// Now let's also look at the broader context around 0x612e7b0-0x612e7d0
var contextAddr = mainBase.add(0x612e7a0);
var contextBytes = contextAddr.readByteArray(64);
hex = Array.from(new Uint8Array(contextBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
console.log("[*] Context 0x612e7a0-0x612e7e0: " + hex);

// Patch the target function to: xor eax, eax; ret (31 C0 C3)
console.log("[*] Patching cert verification function at " + callTarget + " to return 0...");
Memory.protect(callTarget, 3, 'rwx');
callTarget.writeByteArray([0x31, 0xC0, 0xC3]); // xor eax, eax; ret
console.log("[+] Patched! Function now returns 0 (success)");

// Keep the NOP patch on the disconnect call too
var disconnectCall = mainBase.add(0x612e7c0);
var dcBytes = disconnectCall.readByteArray(5);
hex = Array.from(new Uint8Array(dcBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
console.log("[*] Disconnect call bytes: " + hex);
if (hex !== "90 90 90 90 90") {
    Memory.protect(disconnectCall, 5, 'rwx');
    disconnectCall.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90]);
    console.log("[+] Also NOP'd disconnect call");
}

// Network monitoring
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
            var data = args[1].readByteArray(Math.min(len, 128));
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
            var data = this.buf.readByteArray(Math.min(n, 128));
            var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
            console.log("[RECV fd=" + this.fd + " len=" + n + "] " + hex);
        }
    }
});

Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            console.log("[!] BLOCKING closesocket(fd=" + args[0].toInt32() + ")");
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

Interceptor.attach(shutdownAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            console.log("[!] BLOCKING shutdown(fd=" + args[0].toInt32() + ")");
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

console.log("[*] All patches applied. Trigger connection now!");
