/*
 * Frida v7: Hook FUN_146e1cf10 (the RESPONSE handler) to see if it's called.
 * This is the function that processes PreAuth response and triggers Login.
 * If it's called with param_3=0, it processes PreAuth. If param_3!=0, it sends Login.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 v7 === Base=' + base);

// Block disconnects
Interceptor.replace(addr(0x6db3e40), new NativeCallback(function(p1) {
    console.log('[DISCONNECT] BLOCKED');
}, 'void', ['pointer']));

// THE KEY FUNCTION - response handler
Interceptor.attach(addr(0x6e1cf10), {
    onEnter: function(args) {
        console.log('[RESPONSE_HANDLER] >>> CALLED! param1=' + args[0] + ' param2=' + args[1] + ' param3=' + args[2]);
        if (args[2].toInt32() === 0) {
            console.log('[RESPONSE_HANDLER] param3=0 -> PREAUTH RESPONSE PROCESSING');
        } else {
            console.log('[RESPONSE_HANDLER] param3!=0 -> LOGIN ATTEMPT');
        }
    },
    onLeave: function(retval) {
        console.log('[RESPONSE_HANDLER] returned');
    }
});

// Also hook the RPC sender that sends PreAuth
Interceptor.attach(addr(0x6e1d4c0), {
    onEnter: function(args) {
        console.log('[PreAuth_RPC_send] called with callback at param2');
    }
});

// PreAuth completion
Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(args) {
        console.log('[PreAuth_complete] connMgr=' + args[0] + ' result=' + args[1]);
    }
});

// send_RPC
Interceptor.attach(addr(0x6e18170), {
    onEnter: function(args) {
        console.log('[send_RPC] cm=' + args[0] + ' fn=' + args[3]);
    }
});

// post_PreAuth
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) { console.log('[post_PreAuth] >>> CALLED!'); }
});

// PreAuth_processor
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) { console.log('[PreAuth_proc] >>> CALLED!'); }
});

// LOGIN_SENDER
Interceptor.attach(addr(0x6f2a270), {
    onEnter: function(args) { console.log('[LOGIN_SENDER] >>> CALLED!'); }
});

console.log('=== Ready. ===');
