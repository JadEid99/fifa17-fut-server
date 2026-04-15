/*
 * Frida v43: Dump the login type entry at loginSM+0xE0 and try to
 * call FUN_146e1eb70 directly to force a Login RPC.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v43: Dump Login Type Entry + Force Login ===');

var savedLoginSM = null;

Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        savedLoginSM = args[0];
        console.log('[LOGIN-INIT] loginSM=' + savedLoginSM);
    },
    onLeave: function(retval) {
        if (!savedLoginSM) return;
        var sm = savedLoginSM;
        
        try {
            // Dump the login type entry at +0xE0
            var entry = sm.add(0xE0).readPointer();
            console.log('[LOGIN-INIT] Login type entry at +0xE0 = ' + entry);
            
            if (!entry.isNull()) {
                console.log('[LOGIN-INIT] Entry dump (0x40 bytes):');
                var bytes = new Uint8Array(entry.readByteArray(0x40));
                for (var row = 0; row < 0x40; row += 8) {
                    var val = entry.add(row).readPointer();
                    var hex = '';
                    for (var i = 0; i < 8 && row + i < 0x40; i++) {
                        hex += ('0' + bytes[row + i].toString(16)).slice(-2) + ' ';
                    }
                    // Try to read as string
                    var str = '';
                    try { str = val.readUtf8String(30); } catch(e) {}
                    console.log('  +0x' + row.toString(16) + ' = ' + val + ' [' + hex.trim() + ']' + (str && str.length > 2 ? ' "' + str + '"' : ''));
                }
                
                // Check entry[0] — might be a flag or type
                var e0 = entry.readU8();
                console.log('[LOGIN-INIT] entry[0] = ' + e0);
                
                // Check entry+0x18 — used by FUN_146e1dae0 loop
                var e18 = entry.add(0x18).readPointer();
                console.log('[LOGIN-INIT] entry+0x18 = ' + e18);
                if (!e18.isNull()) {
                    // This might be the auth token or login config
                    try {
                        var s18 = e18.readUtf8String(50);
                        console.log('[LOGIN-INIT] entry+0x18 -> "' + s18 + '"');
                    } catch(e) {}
                    // Dump it
                    console.log('[LOGIN-INIT] entry+0x18 dump:');
                    for (var off = 0; off < 0x30; off += 8) {
                        console.log('  +0x' + off.toString(16) + ' = ' + e18.add(off).readPointer());
                    }
                }
            }
            
            // Also dump +0xC8 area (login type count/config)
            console.log('[LOGIN-INIT] +0xC8 area:');
            for (var off = 0xC0; off < 0x100; off += 8) {
                var val = sm.add(off).readPointer();
                if (!val.isNull()) {
                    console.log('  +0x' + off.toString(16) + ' = ' + val);
                }
            }
            
            // Now try to call FUN_146e1eb70 directly
            // FUN_146e1eb70(loginSM, param_2_ptr, param_3_authtoken, 1)
            // param_2 is a pointer to the login type entry
            // param_3 is entry+0x18 (auth token/config)
            var job = sm.add(0x18).readPointer();
            console.log('[LOGIN-INIT] Job handle = ' + job);
            
            if (!job.isNull() && !entry.isNull()) {
                var authConfig = entry.add(0x18).readPointer();
                if (!authConfig.isNull()) {
                    console.log('[FORCE-LOGIN] Attempting FUN_146e1eb70(loginSM, &entry, authConfig, 1)...');
                    var loginSendFn = new NativeFunction(addr(0x6e1eb70), 'uint64', ['pointer', 'pointer', 'pointer', 'int']);
                    try {
                        var result = loginSendFn(sm, sm.add(0xE0), authConfig, 1);
                        console.log('[FORCE-LOGIN] FUN_146e1eb70 returned: ' + result);
                    } catch(e) {
                        console.log('[FORCE-LOGIN] CRASHED: ' + e);
                    }
                } else {
                    console.log('[FORCE-LOGIN] authConfig is null, cannot call');
                }
            }
        } catch(e) {
            console.log('[LOGIN-INIT] Error: ' + e);
        }
    }
});

// Track if Login RPC is actually sent
Interceptor.attach(addr(0x78aa320), {
    onEnter: function(args) {
        console.log('[AUTH-SEND] FUN_1478aa320 CALLED! (sends auth token to server)');
        try {
            // arg1 might be the auth token string
            var s = args[1].readUtf8String(50);
            if (s) console.log('[AUTH-SEND] token: "' + s + '"');
        } catch(e) {}
    }
});

try {
    Interceptor.attach(addr(0x6e1cf10), {
        onEnter: function(args) { console.log('[PA-HANDLER] Called'); }
    });
} catch(e) {}

console.log('=== Frida v43 Ready ===');
