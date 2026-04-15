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
            param2.add(0x13).writeU8(1);  // Persona creation (triggers state transition)
            console.log('[S2] Wrote +0x10=1, +0x13=1, forced R8=0');
        } catch(e) {}
    },
    onLeave: function(retval) {
        console.log('[S2] Handler returned. Now simulating TOS acceptance...');
        
        // The handler called state transition (1,3) which shows OSDK screen.
        // Now we need to simulate TOS acceptance by calling more transitions.
        // The state machine object is at param_1[1] (handler+0x08).
        try {
            var handler = this._param1;
            var sm = handler.add(0x08).readPointer();
            console.log('[S2] State machine = ' + sm);
            
            if (!sm.isNull()) {
                var smVtable = sm.readPointer();
                var transitionFn38 = smVtable.add(0x38).readPointer();
                var transitionFn08 = smVtable.add(0x08).readPointer();
                console.log('[S2] vtable+0x38 = ' + transitionFn38 + ', vtable+0x08 = ' + transitionFn08);
                
                // Use vtable+0x08 (same as the (1,3) transition uses)
                var callTransition = new NativeFunction(transitionFn08, 'void', ['pointer', 'int', 'int']);
                
                // Try transition (0,1) — might mean "complete/proceed"
                console.log('[S2] Calling transition (0,1) via vtable+0x08...');
                try { callTransition(sm, 0, 1); } catch(e) { console.log('[S2] (0,1) error: ' + e); }
                
                console.log('[S2] *** Transitions called! ***');
            }
        } catch(e) {
            console.log('[S2] Transition error: ' + e);
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
