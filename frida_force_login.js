/*
 * Frida v41: Trace the Login job callback and the actual Login RPC send.
 * The job is created but Login never fires. Need to see if the callback runs.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v41: Login Job Callback Trace ===');

// 1. Login job callback at LAB_146e1d730
try {
    Interceptor.attach(addr(0x6e1d730), {
        onEnter: function(args) {
            console.log('[LOGIN-CALLBACK] LAB_146e1d730 CALLED! arg0=' + args[0] + ' arg1=' + args[1]);
        },
        onLeave: function(retval) {
            console.log('[LOGIN-CALLBACK] returned');
        }
    });
    console.log('Hooked Login callback at 0x146e1d730');
} catch(e) { console.log('Could not hook Login callback: ' + e); }

// 2. FUN_146e1e0f0 — the actual Login/Connect function that builds the Login RPC
try {
    Interceptor.attach(addr(0x6e1e0f0), {
        onEnter: function(args) {
            console.log('[LOGIN-SEND] FUN_146e1e0f0 CALLED! (builds Login RPC)');
        },
        onLeave: function(retval) {
            console.log('[LOGIN-SEND] returned');
        }
    });
    console.log('Hooked Login send at 0x146e1e0f0');
} catch(e) { console.log('Could not hook Login send: ' + e); }

// 3. FUN_146e1d4c0 — RPC dispatch (called by Login send)
try {
    Interceptor.attach(addr(0x6e1d4c0), {
        onEnter: function(args) {
            console.log('[RPC-SEND] FUN_146e1d4c0 CALLED!');
        }
    });
} catch(e) {}

// 4. FUN_1478abf10 — job scheduler (runs queued jobs)
try {
    Interceptor.attach(addr(0x78abf10), {
        onEnter: function(args) {
            console.log('[JOB-RUN] FUN_1478abf10 called');
        }
    });
} catch(e) {}

// 5. FUN_146e1dae0 — called by FUN_146e19720 to check if login should proceed
try {
    Interceptor.attach(addr(0x6e1dae0), {
        onEnter: function(args) {
            console.log('[LOGIN-CHECK] FUN_146e1dae0 called param1=' + args[0]);
        },
        onLeave: function(retval) {
            console.log('[LOGIN-CHECK] returned ' + retval);
        }
    });
} catch(e) {}

// 6. FUN_146e19b30 — called when FUN_146e1dae0 returns false
try {
    Interceptor.attach(addr(0x6e19b30), {
        onEnter: function(args) {
            console.log('[LOGIN-ALT] FUN_146e19b30 called (dae0 returned false)');
        }
    });
} catch(e) {}

// 7. PreAuth handler
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[PA-HANDLER] Called'); }
    });
} catch(e) {}

// 8. Login init
try {
    Interceptor.attach(addr(0x6e1c3f0), {
        onEnter: function(args) { console.log('[LOGIN-INIT] Called'); }
    });
} catch(e) {}

// 9. Login start
try {
    Interceptor.attach(addr(0x6e19720), {
        onEnter: function(args) { console.log('[LOGIN-START] Called'); }
    });
} catch(e) {}

console.log('=== Frida v41 Ready ===');
console.log('Watching: Login callback, Login send, job scheduler, login check');
