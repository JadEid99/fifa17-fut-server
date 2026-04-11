/**
 * Frida script v4 - Patch the SSL verification using the call stack we found.
 * 
 * Call stack when cert fails:
 *   FIFA17.exe+0x612d730  <- closesocket caller
 *   FIFA17.exe+0x612e7c5  <- decision point (calls the close function)
 *   FIFA17.exe+0x6126453  <- SSL state machine
 *   FIFA17.exe+0x6db61f6  <- Blaze redirector
 * 
 * We hook the function at +0x612e7c5 (the caller of the close function)
 * and examine what it does. We also hook +0x6126453 to intercept the
 * SSL state machine and force it to continue.
 */

console.log("[*] FIFA 17 SSL Bypass v4 - Targeted Patch");

var mainBase = Process.findModuleByName("FIFA17.exe").base;

// The function that decides to close the socket is called from 0x612e7c5
// That means the CALL instruction is at approximately 0x612e7c0 (5 bytes for a call)
// The function being called (closesocket wrapper) starts at 0x612d730
// 
// Let's hook the function at 0x6126453 which is the SSL state machine
// and the function at 0x612e7c5's parent function

// First, let's read the code around the call sites to understand the flow
var sites = [0x612d730, 0x612e7c5, 0x6126453];
for (var i = 0; i < sites.length; i++) {
    var addr = mainBase.add(sites[i]);
    // Read 32 bytes before and 32 bytes after
    var before = addr.sub(16).readByteArray(64);
    var hex = Array.from(new Uint8Array(before)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' ');
    console.log("[*] Code at +0x" + sites[i].toString(16) + ": " + hex);
}

// The key insight: 0x612e7c5 is a RETURN ADDRESS, meaning the CALL to
// the close function was at 0x612e7c0 (approximately). The function
// containing this call is what we need to patch.
// 
// Let's find the start of the function containing 0x612e7c5 by scanning
// backwards for a function prologue (push rbp; mov rbp, rsp or sub rsp)

// Hook the function at 0x612e7c5 - 5 (the call instruction)
// Actually, let's hook at the return address and modify the return value
// of the function that was called

// Better approach: Hook the function at 0x6126453 (SSL state machine)
// This is called BEFORE the close decision. We can intercept its return
// value and force success.

var sslStateAddr = mainBase.add(0x6126453);
console.log("[*] Hooking SSL state machine at " + sslStateAddr);

// Read the instruction at the return address to understand the call
var callSite = mainBase.add(0x612e7c0); // approximate call instruction
var callBytes = callSite.readByteArray(16);
console.log("[*] Bytes at call site (0x612e7c0): " + Array.from(new Uint8Array(callBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));

// Let's try to hook the function that CONTAINS the closesocket call
// by finding its start. Scan backwards from 0x612d730 for common
// function prologues
var closeCallerAddr = mainBase.add(0x612d730);
console.log("[*] Scanning backwards from closesocket caller for function start...");
for (var off = 0; off < 256; off++) {
    var checkAddr = closeCallerAddr.sub(off);
    var b0 = checkAddr.readU8();
    var b1 = checkAddr.add(1).readU8();
    // Look for: push rbp (0x55), sub rsp (0x48 0x83 0xEC or 0x48 0x81 0xEC)
    // or mov [rsp+...] (0x48 0x89)
    if (b0 === 0x55 || (b0 === 0x48 && b1 === 0x83) || (b0 === 0x48 && b1 === 0x89) || b0 === 0x40 && b1 === 0x53) {
        console.log("[*] Possible function start at offset -" + off + " (" + checkAddr + ")");
        var funcBytes = checkAddr.readByteArray(32);
        console.log("    " + Array.from(new Uint8Array(funcBytes)).map(function(b) { return ('0' + b.toString(16)).slice(-2); }).join(' '));
    }
}

// Now let's also set up the network hooks
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
        if (sslSockets[args[0].toInt32()]) console.log("[SEND len=" + args[2].toInt32() + "]");
    }
});

Interceptor.attach(recvAddr, {
    onEnter: function(args) { this.fd = args[0].toInt32(); },
    onLeave: function(retval) {
        if (sslSockets[this.fd] && retval.toInt32() > 0) console.log("[RECV len=" + retval.toInt32() + "]");
    }
});

// KEY PATCH: Hook closesocket and BLOCK it for SSL sockets
// This prevents the game from closing the connection after cert failure
// Instead, we'll see what happens next
Interceptor.attach(closesocketAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        if (sslSockets[fd]) {
            console.log("[!] BLOCKING closesocket(fd=" + fd + ")!");
            console.log("[!] Stack: " + Thread.backtrace(this.context, Backtracer.ACCURATE).map(function(a) {
                return "FIFA17.exe+0x" + a.sub(mainBase).toString(16);
            }).join(" -> "));
            // Replace fd with invalid value to prevent actual close
            args[0] = ptr(0xFFFFFFFF);
        }
    }
});

console.log("[*] Ready. Trigger connection now.");
