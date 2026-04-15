/*
 * Frida v48: Change command in RPC structure AFTER FUN_146dab760 builds it.
 * Also change the response handler vtable to OriginLogin's.
 *
 * v47 showed: changing cmd at send time works for the wire but the game
 * still uses CreateAccountResponse decoder. Need to change BOTH the
 * command AND the response type in the RPC structure.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v48: Full OriginLogin Redirect ===');

// Hook FUN_146dab760 to intercept CreateAccount RPC build
// Change the command AND response type after the structure is built
Interceptor.attach(addr(0x6dab760), {
    onEnter: function(args) {
        // R8 = command (3rd arg in Microsoft x64)
        var cmd = this.context.r8.toInt32();
        if (cmd === 10) {
            console.log('[RPC-BUILD] CreateAccount detected, changing R8 to 0x98');
            this.context.r8 = ptr(0x98);
            this._wasCreateAccount = true;
            this._rpcObj = args[0]; // RCX = the RPC structure being built
        }
    },
    onLeave: function(retval) {
        if (this._wasCreateAccount && this._rpcObj) {
            // After FUN_146dab760 returns, the RPC structure has the command stored
            // Try to find and change the command in the structure
            // The structure was passed as RCX (first arg)
            var obj = this._rpcObj;
            console.log('[RPC-BUILD] Post-build: scanning RPC structure for cmd value...');
            try {
                // Dump first 0x30 bytes to find where command is stored
                for (var off = 0; off < 0x30; off += 2) {
                    var val = obj.add(off).readU16();
                    if (val === 10) {
                        console.log('[RPC-BUILD] Found cmd=10 at RPC+0x' + off.toString(16) + ', changing to 0x98');
                        obj.add(off).writeU16(0x98);
                    }
                    if (val === 0x0A) {
                        // Same thing, just being explicit
                    }
                }
                // Also check for the response vtable
                // CreateAccountResponse vtable = 0x14389ac68
                // We need to find what OriginLogin response vtable is
                for (var off = 0; off < 0x100; off += 8) {
                    var ptr_val = obj.add(off).readPointer();
                    if (ptr_val.equals(addr(0x389ac68))) {
                        console.log('[RPC-BUILD] Found CreateAccountResponse vtable at RPC+0x' + off.toString(16));
                        // Don't change it yet — we need to know the OriginLogin vtable first
                    }
                }
            } catch(e) {
                console.log('[RPC-BUILD] Scan error: ' + e);
            }
        }
    }
});

// Also hook FUN_146df0e80 to change the command at send time too
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[RPC-SEND] Changing cmd 10->0x98 at send time');
            this.context.r9 = ptr(0x98);
        } else if (comp > 0 && comp < 0x8000) {
            console.log('[RPC-SEND] comp=' + comp + ' cmd=' + cmd);
        }
    }
});

// Hook response decoder to see what happens
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var bodyBufObj = args[3];
        try {
            var bufStart = bodyBufObj.add(0x08).readPointer();
            var bufEnd = bodyBufObj.add(0x18).readPointer();
            var bodyLen = bufEnd.sub(bufStart).toInt32();
            if (bodyLen > 0 && bodyLen < 1000) {
                console.log('[RPC-RESP] bodyLen=' + bodyLen);
            }
        } catch(e) {}
    }
});

// Hook the CreateAccount handler to see response
try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            console.log('[HANDLER] Called R8=' + args[2]);
            try {
                var resp = args[1];
                var vt = resp.readPointer();
                var b10 = resp.add(0x10).readU8();
                var b13 = resp.add(0x13).readU8();
                console.log('[HANDLER] vtable=' + vt + ' +0x10=' + b10 + ' +0x13=' + b13);
            } catch(e) {}
        }
    });
} catch(e) {}

console.log('=== Frida v48 Ready ===');
