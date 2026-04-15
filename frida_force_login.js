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
                var transitionFn = smVtable.add(0x38).readPointer();
                console.log('[S2] Transition function = ' + transitionFn);
                
                // Call transitions to simulate TOS acceptance
                var callTransition = new NativeFunction(transitionFn, 'void', ['pointer', 'int', 'int']);
                
                // Transition (4,1) — TOS loaded
                console.log('[S2] Calling transition (4,1)...');
                callTransition(sm, 4, 1);
                
                // Transition (5,1) — TOS accepted  
                console.log('[S2] Calling transition (5,1)...');
                callTransition(sm, 5, 1);
                
                // Transition (3,1) — proceed to next step
                console.log('[S2] Calling transition (3,1)...');
                callTransition(sm, 3, 1);
                
                console.log('[S2] *** All TOS transitions called! ***');
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
