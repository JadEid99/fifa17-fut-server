/*
 * Frida script: Force Login after PreAuth.
 * When PreAuth completes, we directly call the login type check
 * and if conditions are met, trigger the login connection.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }

console.log('=== FIFA 17 Force Login === Base=' + base);

// Hook PreAuth completion - when it fires, force the login flow
Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(args) {
        this.connMgr = args[0]; // ConnectionManager object
        this.result = args[1];
        console.log('[PreAuth] Complete! connMgr=' + this.connMgr + ' result=' + this.result);
        
        // Read the login state machine from BlazeHub
        try {
            // connMgr+0x8 = inner connection, but we need the BlazeHub
            // The BlazeHub is the parent - connMgr is at BlazeHub+0x750 offset
            // Actually, connMgr IS the ConnectionManager at BlazeHub+0x750
            // The BlazeHub is at connMgr - 0x750... no, that's wrong.
            // Let me read from the known global instead
            var onlineMgr = addr(0x48a3b20).readPointer();
            console.log('[PreAuth] OnlineMgr=' + onlineMgr);
            if (!onlineMgr.isNull()) {
                var connWrapper = onlineMgr.add(0xb10).readPointer();
                if (!connWrapper.isNull()) {
                    var blazeHub = connWrapper.add(0xf8).readPointer();
                    console.log('[PreAuth] BlazeHub=' + blazeHub);
                    if (!blazeHub.isNull()) {
                        var loginSM = blazeHub.add(0x750).readPointer();
                        console.log('[PreAuth] LoginSM=' + loginSM);
                        
                        // The login state machine has the active login type at +0x28
                        if (!loginSM.isNull()) {
                            var activeType = loginSM.add(0x28).readPointer();
                            console.log('[PreAuth] ActiveType=' + activeType);
                            
                            if (!activeType.isNull()) {
                                // Read the vtable check function
                                var vtable = activeType.readPointer();
                                var checkFn = vtable.add(0x10).readPointer();
                                console.log('[PreAuth] CheckFn=' + checkFn);
                                
                                // Call the check function
                                var checkFunc = new NativeFunction(checkFn, 'uint8', ['pointer']);
                                var result = checkFunc(activeType);
                                console.log('[PreAuth] CheckFn result=' + result);
                                
                                if (result !== 0) {
                                    console.log('[PreAuth] >>> Login type says PROCEED! <<<');
                                    // Now we need to call FUN_146e18170 to send the Login RPC
                                    // But we need the right parameters...
                                    // Let's try calling the parent function that handles param_3 != 0
                                    
                                    // The parent function checks param_1[2] vtable and calls FUN_146e18170
                                    // param_1[2] is at loginSM + 0x10
                                    var type2 = loginSM.add(0x10).readPointer();
                                    console.log('[PreAuth] Type2=' + type2);
                                    
                                    // Check type2's vtable[0x10]
                                    if (!type2.isNull()) {
                                        var vt2 = type2.readPointer();
                                        var cf2 = vt2.add(0x10).readPointer();
                                        var check2 = new NativeFunction(cf2, 'uint8', ['pointer']);
                                        var r2 = check2(type2);
                                        console.log('[PreAuth] Type2 check=' + r2);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch(e) {
            console.log('[PreAuth] Error: ' + e.message);
        }
    },
    onLeave: function(retval) {
        console.log('[PreAuth] Handler returned: ' + retval);
    }
});

// Also hook send_RPC to see if Login is ever sent
Interceptor.attach(addr(0x6e18170), {
    onEnter: function(args) {
        console.log('[send_RPC] >>> cm=' + args[0] + ' cb=' + args[2] + ' fn=' + args[3]);
    }
});

// Hook the login sender to see if it's ever called
Interceptor.attach(addr(0x6f2a270), {
    onEnter: function(args) {
        console.log('[LOGIN_SENDER] >>> CALLED! p1=' + args[0]);
    }
});

// Hook disconnect to see when/why it happens
Interceptor.attach(addr(0x6db3e40), {
    onEnter: function(args) {
        console.log('[DISCONNECT] p1=' + args[0]);
    }
});

console.log('=== Ready. Trigger connection. ===');
