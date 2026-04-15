/*
 * Frida v55: INTERCEPT STATE TRANSITION
 *
 * v54 findings:
 * - State (1,3) fires successfully
 * - SM[3]=0x0 confirms state 2 doesn't exist (why 2,1 crashed)
 * - Our (0,-1) call executed but TOO LATE — Logout already sent
 * - The OSDK screen's network thread sends GetLegalDocsInfo/GetTOS/Logout
 *   before our onLeave handler runs
 *
 * v55 strategy:
 * - Hook the state transition function FUN_146e126b0
 * - When we see transition (1,3) from the CreateAccount handler,
 *   CHANGE IT to (0,-1) in-place
 * - This prevents the OSDK state from ever being entered
 * - The state machine goes directly to the completion state
 *
 * Additionally:
 * - Still NOP FUN_146e00f40 (OSDK screen) as safety net
 * - Still write +0x10=1, +0x13=1 in CreateAccount handler
 * - Still redirect CreateAccount→OriginLogin at wire level
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v55: Intercept State Transition ===');

// ============================================================
// Step 1: NOP the OSDK screen loader (safety net)
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
// Step 2: Hook state transition — INTERCEPT (1,3) → (0,-1)
// ============================================================
var createAccountHandlerActive = false;
var stateTransitionCount = 0;

try {
    Interceptor.attach(addr(0x6e126b0), {
        onEnter: function(args) {
            var sm = args[0];
            var state = args[1].toInt32();
            var p3 = args[2].toInt32();
            stateTransitionCount++;
            
            console.log('[STATE #' + stateTransitionCount + '] transition(' + state + ', ' + p3 + ') sm=' + sm);
            
            // Log SM slots
            try {
                var slot5 = sm.add(40).readPointer();
                console.log('[STATE]   current_state(sm[5])=' + slot5);
            } catch(e) {}
            
            // INTERCEPT: If CreateAccount handler triggered (1,3), change to (0,-1)
            if (createAccountHandlerActive && state === 1 && p3 === 3) {
                console.log('[STATE] *** INTERCEPTING (1,3) → changing to (0, -1) ***');
                // Change param_2 from 1 to 0 (go to state 0 instead of state 1)
                args[1] = ptr(0);
                // Change param_3 from 3 to -1 (0xFFFFFFFF) (completion signal)
                args[2] = ptr(0xFFFFFFFF);
                console.log('[STATE] *** Transition changed to (0, -1) ***');
            }
        }
    });
    console.log('[INIT] Hooked state transition with (1,3)→(0,-1) intercept');
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
// Step 5: Intercept CreateAccount handler
// ============================================================
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        console.log('[HANDLER] CreateAccount handler entered');
        
        // Set flag so state transition hook knows to intercept (1,3)
        createAccountHandlerActive = true;
        
        // Force param_3 (R8) = 0 (success path)
        this.context.r8 = ptr(0);
        
        // Write response object fields
        try {
            var resp = args[1];
            resp.add(0x10).writeU8(1);   // UID byte
            resp.add(0x11).writeU8(0);
            resp.add(0x12).writeU8(0);
            resp.add(0x13).writeU8(1);   // persona creation flag → triggers state transition
            console.log('[HANDLER] Wrote +0x10=1, +0x13=1, R8=0');
        } catch(e) { console.log('[HANDLER] Write error: ' + e); }
    },
    onLeave: function(retval) {
        createAccountHandlerActive = false;
        console.log('[HANDLER] CreateAccount handler returned');
    }
});

// ============================================================
// Step 6: Monitor Login/PostAuth/LoginCheck
// ============================================================
try {
    Interceptor.attach(addr(0x6e1eb70), {
        onEnter: function(args) {
            console.log('[LOGIN-SEND] *** FUN_146e1eb70 called! Login RPC being sent! ***');
        },
        onLeave: function(retval) {
            console.log('[LOGIN-SEND] returned ' + retval);
        }
    });
} catch(e) {}

try {
    Interceptor.attach(addr(0x6e213e0), {
        onEnter: function(args) {
            console.log('[POSTAUTH] *** FUN_146e213e0 called! ***');
        }
    });
} catch(e) {}

try {
    Interceptor.attach(addr(0x6e1dae0), {
        onEnter: function(args) {
            var loginSM = args[0];
            try {
                var arrStart = loginSM.add(0x218).readPointer();
                var arrEnd = loginSM.add(0x220).readPointer();
                var count = arrEnd.sub(arrStart).toInt32() / 0x20;
                console.log('[LOGIN-CHECK] FUN_146e1dae0, array count=' + count);
            } catch(e) {
                console.log('[LOGIN-CHECK] FUN_146e1dae0 called');
            }
        },
        onLeave: function(retval) {
            console.log('[LOGIN-CHECK] returned ' + retval);
        }
    });
} catch(e) {}

// Hook FUN_146e19720 (login start / job creator)
try {
    Interceptor.attach(addr(0x6e19720), {
        onEnter: function(args) {
            console.log('[LOGIN-START] FUN_146e19720 called (login job creator)');
        }
    });
} catch(e) {}

// Hook FUN_146e1c3f0 (login type processor - called during PreAuth)
try {
    Interceptor.attach(addr(0x6e1c3f0), {
        onEnter: function(args) {
            console.log('[LOGIN-TYPES] FUN_146e1c3f0 called (login type processor)');
            // args[1] is the login type data from PreAuth response
            var loginData = args[1];
            console.log('[LOGIN-TYPES] loginData ptr = ' + loginData);
        }
    });
} catch(e) {}

console.log('=== Frida v55 Ready ===');
