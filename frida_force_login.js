/*
 * Frida v53: COMPREHENSIVE — based on deep research analysis.
 *
 * The research confirms: we need ALL THREE simultaneously:
 * 1. Write +0x10=1, +0x13=1 (force state transition)
 * 2. NOP FUN_146e00f40 (prevent OSDK screen)
 * 3. After state transition (1,3), call PostAuth to establish session
 *
 * Key insight from BF4 emulator: BF4 uses SilentLogin because the
 * DLL provides a token for an "existing" account. FIFA 17 sends
 * CreateAccount because it thinks the account is new.
 *
 * NEW: After the (1,3) transition advances the state machine,
 * we call FUN_146e213e0 (PostAuth) with the BlazeHub to establish
 * the session. Then the game should send PostAuth RPC to the server.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v53: Comprehensive Auth Bypass ===');

// NOP the OSDK screen loader
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
    console.log('[INIT] NOPed FUN_146e00f40 (OSDK screen)');
} catch(e) { console.log('[INIT] NOP error: ' + e); }

// Redirect CreateAccount→OriginLogin at wire level
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[WIRE] CreateAccount -> OriginLogin');
            this.context.r9 = ptr(0x98);
        }
    }
});

// Intercept CreateAccount handler
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        this._handler = args[0];
        this.context.r8 = ptr(0); // Force success
        
        var param2 = args[1];
        try {
            param2.add(0x10).writeU8(1);  // UID non-zero
            param2.add(0x13).writeU8(1);  // Persona creation (triggers state transition 1,3)
            console.log('[HANDLER] Wrote +0x10=1, +0x13=1, R8=0');
        } catch(e) { console.log('[HANDLER] Write error: ' + e); }
    },
    onLeave: function(retval) {
        console.log('[HANDLER] Returned. State transition (1,3) should have fired.');
        console.log('[HANDLER] Now calling PostAuth to establish session...');
        
        // Get BlazeHub from the PreAuth handler's saved param_1
        // We need g_preAuthParam1 + 0x1DB0 + 0x08 = BlazeHub
        // But we can also get it from the handler's own context
        try {
            var handler = this._handler;
            // handler+0x08 is the state machine
            // The BlazeHub is accessible via the state machine
            // Actually, let's get it from the handler's vtable+0xb8 → state → +0x08
            // Or simpler: read from the global OnlineManager
            var pOM = addr(0x48a3b20).readPointer();
            if (!pOM.isNull()) {
                var cm = pOM.add(0xb10).readPointer();
                if (!cm.isNull()) {
                    var bh = cm.add(0xf8).readPointer();
                    if (!bh.isNull()) {
                        console.log('[POSTAUTH] BlazeHub = ' + bh);
                        
                        // Call FUN_146e213e0(blazeHub, 0)
                        var postAuthFn = new NativeFunction(addr(0x6e213e0), 'void', ['pointer', 'pointer']);
                        postAuthFn(bh, ptr(0));
                        console.log('[POSTAUTH] *** PostAuth called! ***');
                    }
                }
            }
        } catch(e) {
            console.log('[POSTAUTH] Error: ' + e);
        }
    }
});

// Track all RPC sends
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            console.log('[RPC] comp=' + comp + ' cmd=' + cmd + ' (0x' + cmd.toString(16) + ')');
        }
    }
});

// Track state transitions
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            console.log('[STATE] (' + args[1].toInt32() + ',' + args[2].toInt32() + ')');
        }
    });
} catch(e) {}

console.log('=== Frida v53 Ready ===');
