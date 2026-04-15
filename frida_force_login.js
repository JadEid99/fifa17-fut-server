/*
 * Frida v40: Verify Login init functions are called with new Patch 3 (error return).
 * Also trace the Login job to see why it doesn't fire.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v40: Login Flow Trace ===');

// 1. FUN_146e1c3f0 — Login type processor (called by PreAuth handler)
try {
    Interceptor.attach(addr(0x6e1c3f0), {
        onEnter: function(args) {
            console.log('[LOGIN-INIT] FUN_146e1c3f0 CALLED! loginSM=' + args[0] + ' param2=' + args[1]);
            try {
                var bh = args[0].add(0x08).readPointer();
                console.log('[LOGIN-INIT] loginSM+0x08 (BlazeHub) = ' + bh);
                if (!bh.isNull()) {
                    var flag = bh.add(0x53f).readU8();
                    console.log('[LOGIN-INIT] BlazeHub+0x53f = ' + flag);
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            console.log('[LOGIN-INIT] FUN_146e1c3f0 returned');
        }
    });
} catch(e) { console.log('Could not hook FUN_146e1c3f0: ' + e); }

// 2. FUN_146e19720 — Login start (queues the Login job)
try {
    Interceptor.attach(addr(0x6e19720), {
        onEnter: function(args) {
            var sm = args[0];
            console.log('[LOGIN-START] FUN_146e19720 CALLED! param1=' + sm);
            try {
                var guard = sm.add(0x18).readPointer();
                console.log('[LOGIN-START] loginSM+0x18 (guard) = ' + guard);
                var loginType = sm.add(0x1f8).readU16();
                console.log('[LOGIN-START] loginSM+0x1f8 (login type) = ' + loginType);
            } catch(e) {}
        },
        onLeave: function(retval) {
            console.log('[LOGIN-START] FUN_146e19720 returned');
        }
    });
} catch(e) { console.log('Could not hook FUN_146e19720: ' + e); }

// 3. FUN_1478aa0f0 — RPC job creator (creates the Login job)
try {
    Interceptor.attach(addr(0x78aa0f0), {
        onEnter: function(args) {
            console.log('[JOB-CREATE] FUN_1478aa0f0 CALLED! callback=' + args[0] + ' context=' + args[1] + ' param3=' + args[2]);
        },
        onLeave: function(retval) {
            console.log('[JOB-CREATE] returned job=' + retval);
        }
    });
} catch(e) { console.log('Could not hook FUN_1478aa0f0: ' + e); }

// 4. PreAuth handler
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[PA-HANDLER] Called R8=' + args[2]);
        },
        onLeave: function(retval) {
            console.log('[PA-HANDLER] Returned');
        }
    });
} catch(e) {}

// 5. FUN_146e1e460 — post_PreAuth (sends Ping, called before FUN_146e1c3f0)
try {
    Interceptor.attach(addr(0x6e1e460), {
        onEnter: function(args) {
            console.log('[POST-PREAUTH] FUN_146e1e460 CALLED');
        }
    });
} catch(e) {}

// 6. FUN_14717d5d0 — age check (should be patched to RET)
try {
    Interceptor.attach(addr(0x717d5d0), {
        onEnter: function(args) {
            console.log('[AGE-CHECK] FUN_14717d5d0 CALLED (should be NOPed!)');
        }
    });
} catch(e) {}

// 7. Track all Blaze RPC sends to see if Login is sent
try {
    Interceptor.attach(addr(0x6db5a60), {
        onEnter: function(args) {
            console.log('[RPC-DISPATCH] FUN_146db5a60 called');
        }
    });
} catch(e) {}

console.log('=== Frida v40 Ready ===');
