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
            var connMgr = blazeHubAddr.add(0x750).readPointer();
            console.log('[BlazeHub] +0x750 ConnMgr=' + connMgr);
            
            if (connMgr.compare(ptr(0x10000)) > 0) {
                // LoginStateMachine is at ConnMgr + 0x1db0
                var loginSM = connMgr.add(0x1db0);
                console.log('[ConnMgr] LoginSM at ' + loginSM);
                
                // LoginSM layout: [0]=vtable, [+0x08]=type1, [+0x10]=type2, [+0x20]=type4, [+0x28]=active
                var lsmVtable = loginSM.readPointer();
                var active = loginSM.add(0x28).readPointer();
                var type1 = loginSM.add(0x08).readPointer();
                var type2 = loginSM.add(0x10).readPointer();
                console.log('[LoginSM] vtable=' + lsmVtable + ' active=' + active + ' type1=' + type1 + ' type2=' + type2);
                
                if (!active.isNull() && active.compare(ptr(0x10000)) > 0) {
                    var atVtable = active.readPointer();
                    var checkFn = atVtable.add(0x10).readPointer();
                    console.log('[LoginSM] ActiveType vtable=' + atVtable + ' checkFn=' + checkFn);
                    
                    var check = new NativeFunction(checkFn, 'uint8', ['pointer']);
                    var r = check(active);
                    console.log('[LoginSM] >>> CheckFn returned: ' + r + ' <<<');
                    
                    // Read what the check function reads at +0x30
                    try {
                        var val30 = active.add(0x30).readPointer();
                        console.log('[LoginSM] ActiveType+0x30=' + val30);
                    } catch(e2) {}
                } else {
                    console.log('[LoginSM] Active type is NULL or invalid: ' + active);
                }
                
                // Also dump raw bytes around the LoginSM to verify structure
                var raw = loginSM.readByteArray(64);
                console.log('[LoginSM] raw: ' + Array.from(new Uint8Array(raw)).map(function(b){return ('0'+b.toString(16)).slice(-2)}).join(' '));
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
