/**
 * Frida script v7 - Hook the SSL state machine function to trace execution
 * and find the exact point where cert verification fails.
 * 
 * The SSL state machine at 0x6126453 checks a state field at [rbx+0x8C].
 * State 6 is the certificate processing state. Let's trace what happens.
 */

console.log("[*] FIFA 17 SSL Bypass v7 - State Machine Trace");

var mainBase = Process.findModuleByName("FIFA17.exe").base;

// The code at 0x6126463 does: cmp dword [rbx+0x8C], 6; jne ...
// State 6 appears to be the certificate verification state.
// Let's find ALL places where [rbx+0x8C] is set and trace them.

// First, let's hook the recv to track when the game reads the ServerHelloDone
var recvAddr = Module.load("WS2_32.dll").getExportByName("recv");
var sendAddr = Module.load("WS2_32.dll").getExportByName("send");
var connectAddr = Module.load("WS2_32.dll").getExportByName("connect");
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
            console.log("[SEND len=" + args[2].toInt32() + "]");
        }
    }
});

Interceptor.attach(recvAddr, {
    onEnter: function(args) { this.fd = args[0].toInt32(); this.buf = args[1]; this.reqLen = args[2].toInt32(); },
    onLeave: function(retval) {
        var n = retval.toInt32();
        if (sslSockets[this.fd]) {
            if (n > 0) {
                var data = this.buf.readByteArray(Math.min(n, 32));
                var hex = Array.from(new Uint8Array(data)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
                console.log("[RECV fd=" + this.fd + " req=" + this.reqLen + " got=" + n + "] " + hex);
                // Log the call stack for the recv that reads the ServerHelloDone
                if (n === 4 || n === 9 || this.reqLen === 4) {
                    console.log("[RECV] Stack: " + Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 5).map(function(a) {
                        return "+" + a.sub(mainBase).toString(16);
                    }).join(" -> "));
                }
            } else if (n === -1) {
                console.log("[RECV fd=" + this.fd + " ERROR]");
            } else if (n === 0) {
                console.log("[RECV fd=" + this.fd + " CLOSED]");
            }
        }
    }
});

Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        if (sslSockets[args[0].toInt32()]) {
            console.log("[!] closesocket(fd=" + args[0].toInt32() + ")");
            console.log("[!] Stack: " + Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8).map(function(a) {
                return "+" + a.sub(mainBase).toString(16);
            }).join(" -> "));
            // Block it
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

// Now the key: hook the function that's called after receiving the Certificate.
// From the state machine code at 0x6126463:
//   cmp dword [rbx+0x8C], 6
//   jne +0xCB (skip cert processing)
// 
// The cert processing block starts at 0x612646F (after the jne).
// Let's hook the function calls within that block.

// At 0x6126498: call 0x612669C (e8 2d 02 00 00) - this might be the cert processing function
var certProcessCall = mainBase.add(0x612649D);
var certProcessOffset = certProcessCall.readS32();
var certProcessTarget = certProcessCall.add(4).add(certProcessOffset);
console.log("[*] Cert process function at: " + certProcessTarget + " (RVA=0x" + certProcessTarget.sub(mainBase).toString(16) + ")");

// Read its first bytes
var cpBytes = certProcessTarget.readByteArray(32);
console.log("[*] Cert process bytes: " + Array.from(new Uint8Array(cpBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));

// Hook it to see when it's called and what it returns
Interceptor.attach(certProcessTarget, {
    onEnter: function(args) {
        console.log("[CERT_PROCESS] Called! rcx=" + this.context.rcx + " rdx=" + this.context.rdx);
    },
    onLeave: function(retval) {
        console.log("[CERT_PROCESS] Returned: " + retval.toInt32());
        if (retval.toInt32() !== 0) {
            console.log("[CERT_PROCESS] NON-ZERO RETURN! Forcing to 0...");
            retval.replace(0);
        }
    }
});

// Also hook the function at 0x612d5d0 (the one we patched before) to see if it's called
var verifyFunc = mainBase.add(0x612d5d0);
Interceptor.attach(verifyFunc, {
    onEnter: function(args) {
        console.log("[VERIFY_0x612d5d0] Called! rcx=" + this.context.rcx + " rdx=" + this.context.rdx);
    },
    onLeave: function(retval) {
        console.log("[VERIFY_0x612d5d0] Returned: " + retval.toInt32());
        if (retval.toInt32() !== 0) {
            console.log("[VERIFY_0x612d5d0] Forcing to 0!");
            retval.replace(0);
        }
    }
});

console.log("[*] All hooks ready. Trigger connection now!");
