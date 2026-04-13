/*
 * Frida: Force Login after PreAuth.
 * Captures BlazeHub from the handler callback, reads LoginSM from it.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 Force Login v2 === Base=' + base);

var blazeHubAddr = null;

// Hook BlazeHub handler to capture the real BlazeHub address
Interceptor.attach(addr(0x6db7490), {
    onEnter: function(args) {
        blazeHubAddr = args[0];
        var result = args[1];
        console.log('[BlazeHub] handler p1=' + blazeHubAddr + ' result=' + result);
        
        // Read LoginSM from the REAL BlazeHub
        try {
            var loginSM = blazeHubAddr.add(0x750).readPointer();
            console.log('[BlazeHub] +0x750 LoginSM=' + loginSM);
            
            if (loginSM.compare(ptr(0x1000)) > 0) {
                // Looks like a valid pointer
                var activeType = loginSM.add(0x28).readPointer();
                var type1 = loginSM.add(0x08).readPointer();
                var type2 = loginSM.add(0x10).readPointer();
                var type4 = loginSM.add(0x20).readPointer();
                console.log('[LoginSM] +0x08=' + type1 + ' +0x10=' + type2 + ' +0x20=' + type4 + ' +0x28(active)=' + activeType);
                
                if (!activeType.isNull()) {
                    var vtable = activeType.readPointer();
                    var checkFn = vtable.add(0x10).readPointer();
                    console.log('[LoginSM] ActiveType vtable=' + vtable + ' checkFn=' + checkFn);
                    
                    // Call the check function on the game thread
                    var check = new NativeFunction(checkFn, 'uint8', ['pointer']);
                    var r = check(activeType);
                    console.log('[LoginSM] >>> CheckFn returned: ' + r + ' <<<');
                    
                    // Read +0x30 on activeType (this is what the original check function reads)
                    var val30 = activeType.add(0x30).readPointer();
                    console.log('[LoginSM] ActiveType+0x30=' + val30);
                }
                
                // Also check the state at loginSM+0x30 (state field)
                var state = loginSM.add(0x30).readU32();
                console.log('[LoginSM] +0x30 state=' + state);
            } else {
                console.log('[BlazeHub] LoginSM is NOT a valid pointer!');
            }
        } catch(e) {
            console.log('[BlazeHub] Error: ' + e.message);
        }
    }
});

// Hook PreAuth completion
Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(args) {
        console.log('[PreAuth] Complete! connMgr=' + args[0] + ' result=' + args[1]);
    }
});

// Hook send_RPC
Interceptor.attach(addr(0x6e18170), {
    onEnter: function(args) {
        console.log('[send_RPC] cm=' + args[0] + ' cb=' + args[2] + ' fn=' + args[3]);
    }
});

// Hook LOGIN_SENDER
Interceptor.attach(addr(0x6f2a270), {
    onEnter: function(args) {
        console.log('[LOGIN] >>> SENDER CALLED! p1=' + args[0]);
    }
});

// Hook DISCONNECT
Interceptor.attach(addr(0x6db3e40), {
    onEnter: function(args) {
        console.log('[DISCONNECT] p1=' + args[0]);
    }
});

// Hook post_PreAuth
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) {
        console.log('[post_PreAuth] >>> CALLED! p1=' + args[0]);
    }
});

// Hook PreAuth_processor
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        console.log('[PreAuth_proc] >>> CALLED! p1=' + args[0]);
    }
});

console.log('=== Ready. Trigger connection. ===');
