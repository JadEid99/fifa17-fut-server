/*
 * Frida v51: After CreateAccount handler triggers (1,3), immediately
 * simulate TOS acceptance by triggering transitions (4,1), (5,1), (3,1).
 * This should advance past the OSDK screen to Login.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v51: Simulate TOS Acceptance ===');

// NOP the OSDK screen loader
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
    console.log('[INIT] NOPed FUN_146e00f40');
} catch(e) { console.log('[INIT] NOP error: ' + e); }

// Redirect CreateAccount→OriginLogin at send time
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[S1] Redirecting CreateAccount -> OriginLogin');
            this.context.r9 = ptr(0x98);
        }
    }
});

// Intercept CreateAccount handler
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        this._param1 = args[0];
        this.context.r8 = ptr(0); // Force success
        
        var param2 = args[1];
        try {
            param2.add(0x10).writeU8(1);  // UID non-zero
            param2.add(0x11).writeU8(0);
            param2.add(0x12).writeU8(0);
            param2.add(0x13).writeU8(0);  // NO persona creation — handler just returns
            console.log('[S2] Wrote +0x10=1, +0x13=0, forced R8=0');
        } catch(e) {}
    },
    onLeave: function(retval) {
        console.log('[S2] Handler returned. Now calling transition (0,1)...');
        
        try {
            var handler = this._param1;
            var sm = handler.add(0x08).readPointer();
            
            if (!sm.isNull()) {
                var smVtable = sm.readPointer();
                var transitionFn08 = smVtable.add(0x08).readPointer();
                
                // Call (1,3) first to advance state machine (same as persona creation path)
                var callTransition = new NativeFunction(transitionFn08, 'void', ['pointer', 'int', 'int']);
                console.log('[S2] Calling (1,3) to advance state machine...');
                callTransition(sm, 1, 3);
                
                // Then immediately call (0,1) to skip OSDK screen
                console.log('[S2] Calling (0,1) to skip OSDK screen...');
                callTransition(sm, 0, 1);
                
                console.log('[S2] *** Done! ***');
            }
        } catch(e) {
            console.log('[S2] Error: ' + e);
        }
    }
});

// Track state transitions
Interceptor.attach(addr(0x6e126b0), {
    onEnter: function(args) {
        console.log('[TRANSITION] (' + args[1].toInt32() + ',' + args[2].toInt32() + ')');
    }
});

// Track PostAuth
Interceptor.attach(addr(0x6e213e0), {
    onEnter: function(args) {
        console.log('[POSTAUTH] *** FUN_146e213e0 CALLED! ***');
    }
});

// Track any new RPC sends
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            console.log('[RPC] comp=' + comp + ' cmd=' + cmd + ' (0x' + cmd.toString(16) + ')');
        }
    }
});

console.log('=== Frida v51 Ready ===');
