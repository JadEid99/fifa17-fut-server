/*
 * Frida v35: Check if FUN_146e1c3f0 (Login type processor) is called during PreAuth.
 * If not, the loginSM is never initialized and Login can never fire.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v35: Login Init Check ===');

// Hook FUN_146e1c3f0 — is it called during PreAuth?
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        var loginSM = args[0];
        var param2 = args[1];
        console.log('[LOGIN-INIT] FUN_146e1c3f0 CALLED! loginSM=' + loginSM + ' param2=' + param2);
        // Check loginSM+0x08 (BlazeHub)
        try {
            var bh = loginSM.add(0x08).readPointer();
            console.log('[LOGIN-INIT] loginSM+0x08 (BlazeHub) = ' + bh);
            if (!bh.isNull()) {
                var flag = bh.add(0x53f).readU8();
                console.log('[LOGIN-INIT] BlazeHub+0x53f = ' + flag);
            }
        } catch(e) {
            console.log('[LOGIN-INIT] Error reading: ' + e);
        }
    },
    onLeave: function(retval) {
        console.log('[LOGIN-INIT] FUN_146e1c3f0 returned');
    }
});

// Hook FUN_146e19720 — is Login actually started?
Interceptor.attach(addr(0x6e19720), {
    onEnter: function(args) {
        console.log('[LOGIN-START] FUN_146e19720 CALLED! param1=' + args[0]);
    },
    onLeave: function(retval) {
        console.log('[LOGIN-START] FUN_146e19720 returned');
    }
});

// Hook FUN_146e1e460 — post_PreAuth (sends Ping)
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) {
        console.log('[POST-PREAUTH] FUN_146e1e460 CALLED! param1=' + args[0]);
    }
});

// Hook PreAuth handler entry (patched by DLL cave)
try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) {
            console.log('[PA-HANDLER] ENTER RCX=' + args[0] + ' RDX=' + args[1] + ' R8=' + args[2]);
        },
        onLeave: function(retval) {
            console.log('[PA-HANDLER] LEAVE');
        }
    });
} catch(e) {}

// Hook CreateAccount handler entry (patched by DLL cave)
try {
    Interceptor.attach(addr(0x6e151d0), {
        onEnter: function(args) {
            console.log('[CA-HANDLER] ENTER RCX=' + args[0] + ' R8=' + args[2]);
        },
        onLeave: function(retval) {
            console.log('[CA-HANDLER] LEAVE');
        }
    });
} catch(e) {}

console.log('=== Ready — watching for FUN_146e1c3f0 and FUN_146e19720 ===');
