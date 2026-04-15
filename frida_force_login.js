/*
 * Frida v47: Fix OriginLogin redirect — hook FUN_146df0e80 (RPC send)
 * instead of FUN_146dab760 (RPC builder).
 *
 * v46 showed: FUN_146dab760 sets up the structure but FUN_146df0e80
 * reads the command from the structure, not from R8. Need to intercept
 * at the send level.
 *
 * From v46 data: R8=component, R9=command in FUN_146df0e80
 * When R8=1 (Auth) and R9=10 (CreateAccount), change R9 to 0x98 (OriginLogin)
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v47: OriginLogin Redirect at RPC Send ===');

// Hook FUN_146df0e80 — the actual RPC send function
// Change CreateAccount (comp=1, cmd=10) to OriginLogin (comp=1, cmd=0x98)
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[RPC-SEND] *** INTERCEPTED CreateAccount (comp=1,cmd=10) -> OriginLogin (cmd=0x98) ***');
            this.context.r9 = ptr(0x98);
        } else if (comp > 0 && comp < 0x8000) {
            console.log('[RPC-SEND] comp=' + comp + ' cmd=' + cmd + ' (0x' + cmd.toString(16) + ')');
        }
    }
});

// Hook RPC response decoder
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var bodyBufObj = args[3];
        try {
            var bufStart = bodyBufObj.add(0x08).readPointer();
            var bufEnd = bodyBufObj.add(0x18).readPointer();
            var bodyLen = bufEnd.sub(bufStart).toInt32();
            if (bodyLen > 0 && bodyLen < 1000) {
                var hex = '';
                var arr = new Uint8Array(bufStart.readByteArray(Math.min(bodyLen, 32)));
                for (var i = 0; i < arr.length; i++) hex += ('0' + arr[i].toString(16)).slice(-2) + ' ';
                console.log('[RPC-RESP] bodyLen=' + bodyLen + ' first: ' + hex);
            }
        } catch(e) {}
    }
});

// Hook handlers
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[HANDLER] PreAuth R8=' + args[2]); }
    });
} catch(e) {}

try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            console.log('[HANDLER] CreateAccount/OriginLogin R8=' + args[2]);
            try {
                var resp = args[1];
                var b10 = resp.add(0x10).readU8();
                var b13 = resp.add(0x13).readU8();
                console.log('[HANDLER] Response +0x10=' + b10 + ' +0x13=' + b13);
                // Dump vtable to identify which response type
                var vt = resp.readPointer();
                console.log('[HANDLER] Response vtable=' + vt);
            } catch(e) {}
        }
    });
} catch(e) {}

console.log('=== Frida v47 Ready ===');
