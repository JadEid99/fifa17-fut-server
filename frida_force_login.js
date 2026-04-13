/*
 * Frida v9: Don't block disconnects. Just observe the full flow.
 * v7 showed send_RPC was called (Login attempt). Let it complete naturally.
 * Fix type2=NULL so the Login path works.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 v12 === Base=' + base);

// Fix type2=NULL in the response handler
Interceptor.attach(addr(0x6e1cf10), {
    onEnter: function(args) {
        var p1 = args[0];
        var p3 = args[2].toInt32();
        console.log('[RESP] p1=' + p1 + ' p3=0x' + (p3 >>> 0).toString(16));
        
        if (p3 !== 0) {
            // Login path - fix type2 if NULL
            try {
                var type2 = p1.add(0x10).readPointer();
                console.log('[RESP] type2=' + type2);
                if (type2.isNull()) {
                    // Write LoginType0 (at +0x38) into type2
                    var lt0 = p1.add(0x38);
                    var lt0vt = lt0.readPointer();
                    console.log('[RESP] Fixing type2: writing LoginType0 at ' + lt0 + ' (vtable=' + lt0vt + ')');
                    p1.add(0x10).writePointer(lt0);
                    console.log('[RESP] type2 fixed!');
                }
            } catch(e) { console.log('[RESP] Error: ' + e.message); }
        }
    }
});

// Monitor everything
Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(a) { console.log('[PreAuth_done] result=' + a[1]); }
});
Interceptor.attach(addr(0x6e18170), {
    onEnter: function(a) { console.log('[send_RPC] >>> fn=' + a[3]); }
});
// Block BOTH disconnect functions
Interceptor.replace(addr(0x6db3e40), new NativeCallback(function(p1) {
    console.log('[DISCONNECT] BLOCKED');
}, 'void', ['pointer']));

// Also block the connection cleanup function
Interceptor.replace(addr(0x6db8e40), new NativeCallback(function(p1, p2) {
    console.log('[CONN_CLEANUP] BLOCKED');
}, 'void', ['pointer', 'pointer']));
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(a) { console.log('[post_PreAuth] >>> CALLED!'); }
});
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(a) { console.log('[PreAuth_proc] >>> CALLED!'); }
});
Interceptor.attach(addr(0x6f2a270), {
    onEnter: function(a) { console.log('[LOGIN_SENDER] >>> CALLED!'); }
});

console.log('=== Ready. ===');
