/*
 * Frida v46: MULTI-EXPERIMENT — test OriginLogin redirect at runtime
 *
 * Instead of rebuilding the DLL, use Frida to:
 * 1. Intercept FUN_146dab760 (RPC builder) and change cmd 10→0x98
 * 2. Log ALL auth RPC sends to see what commands go out
 * 3. Hook the OriginLogin response handler to see if TDF works
 * 4. Dump the response object after OriginLogin decode
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v46: OriginLogin Redirect (Runtime Patch) ===');

// ============================================================
// EXPERIMENT 1: Intercept FUN_146dab760 to change cmd 10→0x98
// FUN_146dab760(puVar8, loginType, COMMAND, param_7, connection)
// 3rd arg (R8) = command. If 10 (CreateAccount), change to 0x98 (OriginLogin)
// ============================================================
Interceptor.attach(addr(0x6dab760), {
    onEnter: function(args) {
        var cmd = this.context.r8.toInt32();
        if (cmd === 10) {
            console.log('[RPC-BUILD] *** INTERCEPTED cmd=10 (CreateAccount) -> changing to 0x98 (OriginLogin) ***');
            this.context.r8 = ptr(0x98);
        } else if (cmd > 0 && cmd < 0x200) {
            console.log('[RPC-BUILD] cmd=' + cmd + ' (0x' + cmd.toString(16) + ')');
        }
    }
});
console.log('Hooked FUN_146dab760 (RPC builder) — will redirect CreateAccount→OriginLogin');

// ============================================================
// EXPERIMENT 2: Log ALL auth component (0x0001) RPC sends
// Hook FUN_146df0e80 to see what RPCs are dispatched
// ============================================================
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        // args: connection, rpcDesc, loginType, command, ...
        var cmd = this.context.r9.toInt32(); // 4th arg = command
        // Actually in the Ghidra decompilation, the command is the 4th positional arg
        // Let's just log R8 and R9 to see
        var r8 = this.context.r8.toInt32();
        var r9 = this.context.r9.toInt32();
        if (r8 > 0 && r8 < 0x200) {
            console.log('[RPC-SEND] FUN_146df0e80 called, R8=' + r8 + ' (0x' + r8.toString(16) + '), R9=' + r9);
        }
    }
});

// ============================================================
// EXPERIMENT 3: Hook the OriginLogin response handler
// OriginLogin vtable is at 0x14389FA70 (SilentLogin) or nearby
// The response handler is called after the server responds
// ============================================================

// Hook the RPC response decoder to see OriginLogin responses
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var bodyBufObj = args[3];
        try {
            var bufStart = bodyBufObj.add(0x08).readPointer();
            var bufEnd = bodyBufObj.add(0x18).readPointer();
            var bodyLen = bufEnd.sub(bufStart).toInt32();
            if (bodyLen > 0) {
                console.log('[RPC-RESP] Response received, bodyLen=' + bodyLen);
                if (bodyLen > 4 && bodyLen < 500) {
                    var hex = '';
                    var arr = new Uint8Array(bufStart.readByteArray(Math.min(bodyLen, 32)));
                    for (var i = 0; i < arr.length; i++) hex += ('0' + arr[i].toString(16)).slice(-2) + ' ';
                    console.log('[RPC-RESP] First bytes: ' + hex);
                }
            }
        } catch(e) {}
    }
});

// ============================================================
// EXPERIMENT 4: Track handlers
// ============================================================
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[HANDLER] PreAuth called R8=' + args[2]); }
    });
} catch(e) {}

try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            console.log('[HANDLER] CreateAccount/OriginLogin called R8=' + args[2]);
            // Dump param_2 (response object) to see if TDF populated it
            try {
                var resp = args[1];
                var b10 = resp.add(0x10).readU8();
                var b11 = resp.add(0x11).readU8();
                var b12 = resp.add(0x12).readU8();
                var b13 = resp.add(0x13).readU8();
                console.log('[HANDLER] Response +0x10=' + b10 + ' +0x11=' + b11 + ' +0x12=' + b12 + ' +0x13=' + b13);
            } catch(e) {}
        }
    });
} catch(e) {}

// ============================================================
// EXPERIMENT 5: Track if PostAuth is ever requested
// ============================================================
Interceptor.attach(addr(0x6db5a60), {
    onEnter: function(args) {
        // This is the RPC response dispatcher — log all calls
    }
});

console.log('=== Frida v46 Ready ===');
console.log('Will intercept CreateAccount→OriginLogin at FUN_146dab760');
console.log('Will log all RPC sends and responses');
