/*
 * Frida v6: Fix type2=NULL in LoginStateMachine, then trigger Login.
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 Force Login v6 === Base=' + base);

// Block all disconnects
Interceptor.replace(addr(0x6db3e40), new NativeCallback(function(p1) {
    console.log('[DISCONNECT] BLOCKED');
}, 'void', ['pointer']));

var preAuthCount = 0;

Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(args) {
        preAuthCount++;
        var connMgr = args[0];
        console.log('[PreAuth #' + preAuthCount + '] connMgr=' + connMgr);
        
        try {
            // Get the BlazeHub
            var blazeHub = connMgr.add(0x8).readPointer();
            // ConnMgr is at BlazeHub+0x750
            var connMgrFromHub = blazeHub.add(0x750).readPointer();
            console.log('[Fix] BlazeHub=' + blazeHub + ' ConnMgr(from hub)=' + connMgrFromHub);
            
            // LoginSM is at ConnMgr+0x1db0
            var loginSM = connMgrFromHub.add(0x1db0);
            console.log('[Fix] LoginSM=' + loginSM);
            
            // Dump LoginSM structure
            var raw = loginSM.readByteArray(80);
            var bytes = Array.from(new Uint8Array(raw));
            console.log('[Fix] LoginSM raw (80 bytes):');
            for (var i = 0; i < 80; i += 8) {
                var val = loginSM.add(i).readPointer();
                console.log('[Fix]   +0x' + i.toString(16) + ' = ' + val);
            }
            
            // Check type2 at +0x10
            var type2 = loginSM.add(0x10).readPointer();
            console.log('[Fix] type2=' + type2);
            
            if (type2.isNull()) {
                console.log('[Fix] >>> type2 is NULL! Looking for SilentLogin type object... <<<');
                
                // The SilentLogin type should be at loginSM + 0x510 (offset 0xa2*8)
                // Let's check if there's a valid object there
                var silentLoginType = loginSM.add(0x510);
                var slVtable = silentLoginType.readPointer();
                console.log('[Fix] SilentLogin candidate at ' + silentLoginType + ' vtable=' + slVtable);
                
                // Also check loginSM + 0x560 (offset 0xac*8) for ExpressLogin
                var expressLoginType = loginSM.add(0x560);
                var elVtable = expressLoginType.readPointer();
                console.log('[Fix] ExpressLogin candidate at ' + expressLoginType + ' vtable=' + elVtable);
                
                // Check loginSM + 0x38 (offset 0x07*8) for Login type 0
                var loginType0 = loginSM.add(0x38);
                var lt0Vtable = loginType0.readPointer();
                console.log('[Fix] LoginType0 candidate at ' + loginType0 + ' vtable=' + lt0Vtable);
                
                // If any of these have valid vtables (in code section), use it
                if (slVtable.compare(addr(0)) > 0 && slVtable.compare(addr(0x10000000)) < 0) {
                    console.log('[Fix] >>> Writing SilentLogin type into type2! <<<');
                    loginSM.add(0x10).writePointer(silentLoginType);
                    console.log('[Fix] type2 is now: ' + loginSM.add(0x10).readPointer());
                } else if (lt0Vtable.compare(addr(0)) > 0 && lt0Vtable.compare(addr(0x10000000)) < 0) {
                    console.log('[Fix] >>> Writing LoginType0 into type2! <<<');
                    loginSM.add(0x10).writePointer(loginType0);
                    console.log('[Fix] type2 is now: ' + loginSM.add(0x10).readPointer());
                } else {
                    console.log('[Fix] No valid login type found to write');
                }
            } else {
                console.log('[Fix] type2 is already set: ' + type2);
            }
        } catch(e) {
            console.log('[Fix] Error: ' + e.message);
        }
    }
});

Interceptor.attach(addr(0x6e18170), { onEnter: function(a) { console.log('[send_RPC] >>> CALLED!'); } });
Interceptor.attach(addr(0x6f2a270), { onEnter: function(a) { console.log('[LOGIN_SENDER] >>> CALLED!'); } });
Interceptor.attach(addr(0x6e1e460), { onEnter: function(a) { console.log('[post_PreAuth] >>> CALLED!'); } });
Interceptor.attach(addr(0x6e1c3f0), { onEnter: function(a) { console.log('[PreAuth_proc] >>> CALLED!'); } });

console.log('=== Ready. ===');
