/*
 * Frida v42: Dump loginSM array and trace FUN_146e1eb70 to understand
 * what's needed to send the Login RPC.
 *
 * Also: try calling FUN_146e1eb70 directly with fake parameters
 * to force a Login RPC send.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v42: Force Login RPC ===');

// Hook FUN_146e1c3f0 to capture loginSM and dump the array
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        this._loginSM = args[0];
        console.log('[LOGIN-INIT] loginSM=' + args[0]);
    },
    onLeave: function(retval) {
        var sm = this._loginSM;
        try {
            var arrStart = sm.add(0x218).readPointer();
            var arrEnd = sm.add(0x220).readPointer();
            var count = arrEnd.sub(arrStart).toInt32() / 0x20;
            console.log('[LOGIN-INIT] Array: start=' + arrStart + ' end=' + arrEnd + ' count=' + count);
            
            // Also check +0x1b8 (where vtable+0x18 writes)
            console.log('[LOGIN-INIT] +0x1b8 dump:');
            for (var off = 0x1b0; off < 0x230; off += 8) {
                var val = sm.add(off).readPointer();
                if (!val.isNull()) {
                    console.log('  +0x' + off.toString(16) + ' = ' + val);
                }
            }
            
            // Check +0xb8 (login type manager)
            var mgr = sm.add(0xb8);
            console.log('[LOGIN-INIT] Login type manager at +0xb8:');
            for (var off = 0; off < 0x40; off += 8) {
                console.log('  mgr+0x' + off.toString(16) + ' = ' + mgr.add(off).readPointer());
            }
            
            // Check +0xC8 (login type count area)
            var c8val = sm.add(0xC8).readPointer();
            console.log('[LOGIN-INIT] +0xC8 = ' + c8val);
            var e0val = sm.add(0xE0).readPointer();
            console.log('[LOGIN-INIT] +0xE0 = ' + e0val);
            
            // Check the job at +0x18
            var job = sm.add(0x18).readPointer();
            console.log('[LOGIN-INIT] +0x18 (job) = ' + job);
            
            // Check BlazeHub
            var bh = sm.add(0x08).readPointer();
            console.log('[LOGIN-INIT] +0x08 (BlazeHub) = ' + bh);
            if (!bh.isNull()) {
                // Read BlazeHub+0x788 (used by FUN_146e1eb70)
                var v788 = bh.add(0x788).readPointer();
                console.log('[LOGIN-INIT] BlazeHub+0x788 = ' + v788);
            }
        } catch(e) {
            console.log('[LOGIN-INIT] Error: ' + e);
        }
    }
});

// Hook FUN_146e1dae0 to see what it does with the patched return
Interceptor.attach(addr(0x6e1dae0), {
    onEnter: function(args) {
        console.log('[LOGIN-CHECK] Called (should return 1 from patch)');
    },
    onLeave: function(retval) {
        console.log('[LOGIN-CHECK] Returned: ' + retval);
    }
});

// Hook FUN_146e1eb70 to see if it's called
Interceptor.attach(addr(0x6e1eb70), {
    onEnter: function(args) {
        console.log('[LOGIN-SEND] FUN_146e1eb70 CALLED! param1=' + args[0] + ' param2=' + args[1] + ' param3=' + args[2] + ' param4=' + args[3]);
    },
    onLeave: function(retval) {
        console.log('[LOGIN-SEND] returned ' + retval);
    }
});

// Hook FUN_146e19b30 (alt path when login check fails)
Interceptor.attach(addr(0x6e19b30), {
    onEnter: function(args) {
        console.log('[LOGIN-ALT] FUN_146e19b30 called (login check failed path)');
    }
});

// Hook PreAuth handler
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[PA-HANDLER] Called'); }
    });
} catch(e) {}

// Hook FUN_146e19720
Interceptor.attach(addr(0x6e19720), {
    onEnter: function(args) { console.log('[LOGIN-START] Called'); }
});

console.log('=== Frida v42 Ready ===');
