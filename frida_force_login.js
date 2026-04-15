/*
 * Frida v39: Dump the CreateAccount response object (param_2) as received
 * by the handler to see what the TDF decoder populated.
 *
 * The handler reads response[0x10], [0x11], [0x12], [0x13].
 * If [0x10] is non-zero and [0x13] is zero, the handler takes the
 * "account exists, no persona needed" path and returns normally.
 *
 * Our DLL cave bypasses the handler. But if the TDF decoder already
 * populated these fields correctly, we could let the original handler run.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v39: Dump CreateAccount Response Object ===');

// The DLL cave replaces the handler. We need to hook BEFORE the cave runs.
// The cave is at the start of FUN_146e151d0. The RPC framework calls the
// handler with (param_1=RCX, param_2=RDX, param_3=R8).
// param_2 is the decoded response object.

// Hook the RPC response decoder to capture param_2 for CreateAccount
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var bodyBufObj = args[3];
        try {
            var bufStart = bodyBufObj.add(0x08).readPointer();
            var bufEnd = bodyBufObj.add(0x18).readPointer();
            var bodyLen = bufEnd.sub(bufStart).toInt32();
            if (bodyLen > 4) {
                var arr = new Uint8Array(bufStart.readByteArray(4));
                if (arr[0] === 0x86 && arr[1] === 0x7d && arr[2] === 0x70) {
                    this._isCA = true;
                    console.log('[RPC] CreateAccount response entering decoder (bodyLen=' + bodyLen + ')');
                }
            }
        } catch(e) {}
    },
    onLeave: function(retval) {
        if (this._isCA) {
            console.log('[RPC] CreateAccount response decoder returned');
        }
    }
});

// Hook the CA handler (DLL cave entry point)
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var param1 = args[0]; // handler object (RCX)
        var param2 = args[1]; // response object (RDX) — this is what we need
        var param3 = args[2]; // error code (R8)
        
        console.log('\n[CA-HANDLER] Called! param1=' + param1 + ' param2=' + param2 + ' param3=' + param3);
        
        // Dump the response object (param_2)
        try {
            console.log('[CA-HANDLER] Response object (param_2) dump:');
            for (var off = 0; off < 0x20; off += 8) {
                var val = param2.add(off).readPointer();
                console.log('  +0x' + off.toString(16) + ' = ' + val);
            }
            
            // The critical bytes:
            var b10 = param2.add(0x10).readU8();
            var b11 = param2.add(0x11).readU8();
            var b12 = param2.add(0x12).readU8();
            var b13 = param2.add(0x13).readU8();
            console.log('[CA-HANDLER] Critical bytes: +0x10=' + b10 + ' +0x11=' + b11 + ' +0x12=' + b12 + ' +0x13=' + b13);
            
            if (b10 !== 0) {
                console.log('[CA-HANDLER] *** +0x10 is NON-ZERO! UID exists! ***');
            } else {
                console.log('[CA-HANDLER] +0x10 is ZERO — UID not set by TDF decoder');
            }
            if (b13 !== 0) {
                console.log('[CA-HANDLER] +0x13 is NON-ZERO — persona creation needed');
            } else {
                console.log('[CA-HANDLER] +0x13 is ZERO — no persona creation');
            }
        } catch(e) {
            console.log('[CA-HANDLER] Error reading param2: ' + e);
        }
        
        // Also dump param1 (handler) for reference
        try {
            var vtable = param1.readPointer();
            console.log('[CA-HANDLER] Handler vtable: ' + vtable);
        } catch(e) {}
    }
});

// Hook PreAuth handler for comparison
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[PA-HANDLER] Called R8=' + args[2]);
        }
    });
} catch(e) {}

console.log('=== Frida v39 Ready ===');
console.log('Will dump CreateAccount response object bytes at +0x10-0x13');
