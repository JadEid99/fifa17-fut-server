/*
 * Frida v8: Force param_3=0 in response handler to trigger PreAuth processing.
 * This makes the game process the PreAuth response properly and set up the Login callback.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 v8 === Base=' + base);

// Block disconnects
Interceptor.replace(addr(0x6db3e40), new NativeCallback(function(p1) {
    console.log('[DISCONNECT] BLOCKED');
}, 'void', ['pointer']));

// THE FIX: Replace response handler to force param_3=0
var originalHandler = new NativeFunction(addr(0x6e1cf10), 'void', ['pointer', 'pointer', 'int']);
Interceptor.replace(addr(0x6e1cf10), new NativeCallback(function(param1, param2, param3) {
    console.log('[RESPONSE_HANDLER] param1=' + param1 + ' param2=' + param2 + ' param3=0x' + param3.toString(16));
    
    if (param3 !== 0) {
        console.log('[RESPONSE_HANDLER] >>> FORCING param3=0 to trigger PreAuth processing! <<<');
        originalHandler(param1, param2, 0);
    } else {
        originalHandler(param1, param2, param3);
    }
    
    console.log('[RESPONSE_HANDLER] returned');
}, 'void', ['pointer', 'pointer', 'int']));

// Monitor what happens after
Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(args) { console.log('[PreAuth_complete] result=' + args[1]); }
});
Interceptor.attach(addr(0x6e18170), {
    onEnter: function(args) { console.log('[send_RPC] >>> fn=' + args[3]); }
});
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) { console.log('[post_PreAuth] >>> CALLED!'); }
});
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) { console.log('[PreAuth_proc] >>> CALLED!'); }
});
Interceptor.attach(addr(0x6f2a270), {
    onEnter: function(args) { console.log('[LOGIN_SENDER] >>> CALLED!'); }
});

console.log('=== Ready. ===');
