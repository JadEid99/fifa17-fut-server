/*
 * Frida v54: OSDK COMPLETION BYPASS
 *
 * KEY DISCOVERY from Ghidra:
 * FUN_146e15320 (OSDK completion handler) calls state transition (0, 0xFFFFFFFF).
 * This is what fires when the OSDK account creation screen finishes.
 * 
 * Instead of trying state (2,1) which crashed, we:
 * 1. Let CreateAccount handler run with +0x10=1, +0x13=1 → triggers state (1,3)
 * 2. NOP FUN_146e00f40 → prevents OSDK screen from loading
 * 3. After handler returns, call state transition (0, 0xFFFFFFFF) → simulates OSDK completion
 * 4. Then call the completion callback (FUN_146e15320's callback mechanism)
 *
 * The state machine should then advance to the Login phase.
 *
 * ALSO: We hook the state transition function to log ALL transitions and understand the flow.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v54: OSDK Completion Bypass ===');

// ============================================================
// Step 1: NOP the OSDK screen loader (FUN_146e00f40)
// ============================================================
try {
    Memory.patchCode(addr(0x6e00f40), 4, function(code) {
        var w = new X86Writer(code, { pc: addr(0x6e00f40) });
        w.putRet();
        w.flush();
    });
    console.log('[INIT] NOPed FUN_146e00f40 (OSDK screen loader)');
} catch(e) { console.log('[INIT] NOP error: ' + e); }

// ============================================================
// Step 2: Track ALL state transitions
// ============================================================
var stateTransitionCount = 0;
try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            var sm = args[0];
            var state = args[1].toInt32();
            var p3 = args[2].toInt32();
            var p4 = args[3] ? args[3].toInt32() : 0;
            stateTransitionCount++;
            console.log('[STATE #' + stateTransitionCount + '] transition(' + state + ', ' + p3 + ') sm=' + sm);
            
            // Log the state machine's current state slots
            try {
                var slot1 = sm.add(8).readPointer();   // sm[1] = state 0 handler
                var slot2 = sm.add(16).readPointer();  // sm[2] = state 1 handler
                var slot3 = sm.add(24).readPointer();  // sm[3] = state 2 handler
                var slot5 = sm.add(40).readPointer();  // sm[5] = current state
                console.log('[STATE]   sm[1]=' + slot1 + ' sm[2]=' + slot2 + ' sm[3]=' + slot3 + ' sm[5]=' + slot5);
            } catch(e) {}
        }
    });
    console.log('[INIT] Hooked state transition function');
} catch(e) { console.log('[INIT] State hook error: ' + e); }

// ============================================================
// Step 3: Redirect CreateAccount→OriginLogin at wire level
// ============================================================
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp === 1 && cmd === 10) {
            console.log('[WIRE] CreateAccount(0x0A) -> OriginLogin(0x98)');
            this.context.r9 = ptr(0x98);
        }
    }
});

// ============================================================
// Step 4: Track ALL RPC sends
// ============================================================
Interceptor.attach(addr(0x6df0e80), {
    onEnter: function(args) {
        var comp = this.context.r8.toInt32();
        var cmd = this.context.r9.toInt32();
        if (comp > 0 && comp < 0x8000) {
            var cmdNames = {
                0x0A: 'CreateAccount', 0x28: 'Login', 0x32: 'SilentLogin',
                0x3C: 'ExpressLogin', 0x46: 'Logout', 0x98: 'OriginLogin',
                0x07: 'PreAuth', 0x08: 'PostAuth', 0x01: 'FetchClientConfig',
                0x02: 'Ping', 0xF2: 'GetLegalDocsInfo', 0xF6: 'GetTOS',
                0x2F: 'GetPrivacyPolicy', 0x1D: 'ListEntitlements2',
                0x64: 'ListPersonas'
            };
            var name = cmdNames[cmd] || ('0x' + cmd.toString(16));
            console.log('[RPC] comp=0x' + comp.toString(16) + ' cmd=' + name + ' (' + cmd + ')');
        }
    }
});

// ============================================================
// Step 5: Intercept CreateAccount handler — the core bypass
// ============================================================
var savedStateMachine = null;
var savedHandler = null;
var handlerCallCount = 0;

Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        handlerCallCount++;
        console.log('[HANDLER #' + handlerCallCount + '] CreateAccount handler entered');
        
        this._param1 = args[0];  // handler object (longlong *param_1)
        this._param2 = args[1];  // response object (param_2)
        
        // Force param_3 (R8) = 0 (success path)
        this.context.r8 = ptr(0);
        
        // Write response object fields
        try {
            var resp = args[1];
            resp.add(0x10).writeU8(1);   // UID byte (non-zero = account exists)
            resp.add(0x11).writeU8(0);   // extra field 1
            resp.add(0x12).writeU8(0);   // extra field 2  
            resp.add(0x13).writeU8(1);   // persona creation flag (triggers state 1,3)
            console.log('[HANDLER] Wrote +0x10=1, +0x11=0, +0x12=0, +0x13=1, R8=0');
        } catch(e) { console.log('[HANDLER] Write error: ' + e); }
        
        // Save the state machine pointer for later use
        try {
            var param1 = args[0];
            // param_1[1] is the state machine
            var sm = param1.add(8).readPointer();
            savedStateMachine = sm;
            savedHandler = param1;
            console.log('[HANDLER] State machine = ' + sm);
            
            // Log state machine slots
            if (!sm.isNull()) {
                var vtable = sm.readPointer();
                console.log('[HANDLER] SM vtable = ' + vtable);
                // sm[1] through sm[5]
                for (var i = 1; i <= 5; i++) {
                    var slot = sm.add(i * 8).readPointer();
                    console.log('[HANDLER] SM[' + i + '] = ' + slot);
                }
            }
        } catch(e) { console.log('[HANDLER] SM read error: ' + e); }
    },
    onLeave: function(retval) {
        console.log('[HANDLER] CreateAccount handler returned');
        console.log('[HANDLER] State transition (1,3) should have fired (OSDK path)');
        console.log('[HANDLER] Now simulating OSDK completion with transition (0, -1)...');
        
        // After the handler returns, the state machine is in state 1 (OSDK screen).
        // FUN_146e15320 (OSDK completion) calls transition (0, 0xFFFFFFFF).
        // We simulate this to skip the OSDK screen entirely.
        
        if (savedStateMachine !== null && !savedStateMachine.isNull()) {
            try {
                // Small delay to let the state (1,3) transition complete
                // Then call the state transition function directly
                var sm = savedStateMachine;
                
                // Read the transition function from the SM vtable
                // The handler calls: (**(code **)(*(longlong *)param_1[1] + 8))(sm, state, param)
                // So the transition function is at vtable+8
                var vtable = sm.readPointer();
                var transitionFnPtr = vtable.add(8).readPointer();
                console.log('[COMPLETION] Transition function = ' + transitionFnPtr);
                
                // Call transition(sm, 0, 0xFFFFFFFF) — same as FUN_146e15320 does
                var transitionFn = new NativeFunction(transitionFnPtr, 'void', ['pointer', 'int', 'int']);
                
                // First, let's also call the vtable+0xa8 function that FUN_146e15320 calls
                // (**(code **)(*param_1 + 0xa8))() — this is called on the handler object
                if (savedHandler !== null) {
                    try {
                        var handlerVtable = savedHandler.readPointer();
                        var cleanupFnPtr = handlerVtable.add(0xa8).readPointer();
                        console.log('[COMPLETION] Cleanup function (vtable+0xa8) = ' + cleanupFnPtr);
                        var cleanupFn = new NativeFunction(cleanupFnPtr, 'void', ['pointer']);
                        cleanupFn(savedHandler);
                        console.log('[COMPLETION] Cleanup called');
                    } catch(e) { console.log('[COMPLETION] Cleanup error: ' + e); }
                }
                
                // Now call the state transition (0, -1)
                console.log('[COMPLETION] Calling transition(0, -1)...');
                transitionFn(sm, 0, -1);
                console.log('[COMPLETION] *** State transition (0, -1) called! ***');
                
            } catch(e) {
                console.log('[COMPLETION] Error: ' + e);
                console.log('[COMPLETION] Stack: ' + e.stack);
            }
        } else {
            console.log('[COMPLETION] No state machine saved!');
        }
    }
});

// ============================================================
// Step 6: Monitor for Login/PostAuth success
// ============================================================
// Hook the Login handler to see if we reach it
try {
    Interceptor.attach(addr(0x6e1eb70), {
        onEnter: function(args) {
            console.log('[LOGIN-SEND] *** FUN_146e1eb70 called! Login RPC being sent! ***');
            console.log('[LOGIN-SEND] param_1=' + args[0] + ' param_2=' + args[1]);
        },
        onLeave: function(retval) {
            console.log('[LOGIN-SEND] returned ' + retval);
        }
    });
    console.log('[INIT] Hooked Login RPC sender');
} catch(e) {}

// Hook PostAuth setup
try {
    Interceptor.attach(addr(0x6e213e0), {
        onEnter: function(args) {
            console.log('[POSTAUTH] *** FUN_146e213e0 called! PostAuth setup! ***');
        }
    });
    console.log('[INIT] Hooked PostAuth setup');
} catch(e) {}

// Hook the login check function
try {
    Interceptor.attach(addr(0x6e1dae0), {
        onEnter: function(args) {
            var loginSM = args[0];
            var arrStart = loginSM.add(0x218).readPointer();
            var arrEnd = loginSM.add(0x220).readPointer();
            var count = arrEnd.sub(arrStart).toInt32() / 0x20;
            console.log('[LOGIN-CHECK] FUN_146e1dae0 called, array count=' + count);
        },
        onLeave: function(retval) {
            console.log('[LOGIN-CHECK] returned ' + retval);
        }
    });
    console.log('[INIT] Hooked login check');
} catch(e) {}

console.log('=== Frida v54 Ready ===');
