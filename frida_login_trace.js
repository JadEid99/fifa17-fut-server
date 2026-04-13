/**
 * Frida script to trace the FIFA 17 login flow.
 * 
 * Usage:
 *   1. Launch FIFA 17 normally (with our DLL)
 *   2. Wait for it to reach the main menu
 *   3. Run: frida -p <PID> -l frida_login_trace.js
 *      (get PID from Task Manager for FIFA17.exe)
 *   4. Press Q in the game to trigger a connection
 *   5. Copy the Frida console output and save to frida_results.txt
 *   6. Push to git
 */

var base = Process.getModuleByName('FIFA17.exe').base;

function addr(offset) {
    return base.add(offset);
}

function hookFunc(offset, name, onEnter, onLeave) {
    try {
        Interceptor.attach(addr(offset), {
            onEnter: onEnter || function(args) {
                console.log('[CALL] ' + name);
            },
            onLeave: onLeave || function(retval) {
                console.log('[RET]  ' + name + ' -> ' + retval);
            }
        });
        console.log('[HOOK] ' + name + ' at ' + addr(offset));
    } catch(e) {
        console.log('[FAIL] ' + name + ': ' + e.message);
    }
}

console.log('=== FIFA 17 Login Flow Tracer ===');
console.log('Base: ' + base);

// 1. FUN_1471a5da0 - SDK gate (should return 1 with our patch)
hookFunc(0x31a5da0, 'FUN_1471a5da0 (SDK gate)');

// 2. FUN_1471995b0 - returns DAT_144b86bf8 (SDK manager)
hookFunc(0x31995b0, 'FUN_1471995b0 (get SDK mgr)', null, function(retval) {
    console.log('[RET]  FUN_1471995b0 -> ' + retval + (retval.isNull() ? ' *** NULL! ***' : ''));
});

// 3. FUN_146e19a00 - PreAuth completion handler
hookFunc(0x2e19a00, 'FUN_146e19a00 (PreAuth complete)', function(args) {
    console.log('[CALL] FUN_146e19a00 param1=' + args[0] + ' param2=' + args[1] + ' param3=' + args[2]);
});

// 4. FUN_146db3e40 - Blaze disconnect
hookFunc(0x2db3e40, 'FUN_146db3e40 (Blaze disconnect)', function(args) {
    console.log('[CALL] FUN_146db3e40 (DISCONNECT) param1=' + args[0]);
});

// 5. FUN_146db6af0 - Login state machine setup (creates ConnectionManager)
hookFunc(0x2db6af0, 'FUN_146db6af0 (LoginSM setup)', function(args) {
    console.log('[CALL] FUN_146db6af0 param1=' + args[0]);
}, function(retval) {
    console.log('[RET]  FUN_146db6af0 -> ' + retval + (retval.isNull() ? ' *** FAILED! ***' : ' (LoginSM created)'));
});

// 6. FUN_146e19680 - ConnectionManager creation
hookFunc(0x2e19680, 'FUN_146e19680 (ConnMgr create)', function(args) {
    console.log('[CALL] FUN_146e19680 param1=' + args[0]);
}, function(retval) {
    console.log('[RET]  FUN_146e19680 -> ' + retval + (retval.isNull() ? ' *** NULL! ***' : ''));
});

// 7. FUN_146e18170 - Send Blaze RPC (this sends PreAuth, Login, etc.)
hookFunc(0x2e18170, 'FUN_146e18170 (send RPC)', function(args) {
    console.log('[CALL] FUN_146e18170 (SEND RPC) connMgr=' + args[0] + ' callback=' + args[2] + ' callbackFn=' + args[3]);
});

// 8. FUN_146e1e460 - Post-PreAuth handler (sends fetchClientConfig)
hookFunc(0x2e1e460, 'FUN_146e1e460 (post-PreAuth)', function(args) {
    console.log('[CALL] FUN_146e1e460 param1=' + args[0]);
});

// 9. FUN_146e1c3f0 - PreAuth response processor (sets up callback chain)
hookFunc(0x2e1c3f0, 'FUN_146e1c3f0 (PreAuth processor)', function(args) {
    console.log('[CALL] FUN_146e1c3f0 param1=' + args[0] + ' param2=' + args[1]);
});

// 10. FUN_146f2a270 - Login sender (the function that actually sends Login)
hookFunc(0x2f2a270, 'FUN_146f2a270 (LOGIN SENDER)', function(args) {
    console.log('[CALL] *** FUN_146f2a270 LOGIN SENDER *** param1=' + args[0]);
});

// 11. FUN_146da9570 - Schedule async callback
hookFunc(0x2da9570, 'FUN_146da9570 (schedule callback)', function(args) {
    console.log('[CALL] FUN_146da9570 obj=' + args[0] + ' callback=' + args[1] + ' param=' + args[2]);
});

// 12. FUN_146dad43c - Callback dispatcher
hookFunc(0x2dad43c, 'FUN_146dad43c (callback dispatch)', function(args) {
    console.log('[CALL] FUN_146dad43c param1=' + args[0]);
    // Read the vtable function that will be called
    try {
        var obj = args[0];
        var vtable = obj.readPointer();
        var func = vtable.add(0x10).readPointer();
        console.log('       -> vtable=' + vtable + ' func[0x10]=' + func);
    } catch(e) {}
});

// 13. FUN_146e156a0 - Login type check (patched to return 1)
hookFunc(0x2e156a0, 'FUN_146e156a0 (login type check)');

// 14. FUN_146f199c0 - Auth token request processor
hookFunc(0x2f199c0, 'FUN_146f199c0 (auth token proc)', function(args) {
    console.log('[CALL] FUN_146f199c0 param1=' + args[0]);
});

// 15. FUN_1470db3c0 - OriginRequestAuthCodeSync (patched)
hookFunc(0x30db3c0, 'FUN_1470db3c0 (AuthCodeSync)', function(args) {
    console.log('[CALL] FUN_1470db3c0 param1=' + args[0] + ' param2=' + args[1]);
}, function(retval) {
    console.log('[RET]  FUN_1470db3c0 -> ' + retval);
});

// 16. FUN_146124a40 - DirtySDK status check (used in BlazeHub init)
hookFunc(0x2124a40, 'FUN_146124a40 (DirtySDK status)', function(args) {
    var tag = args[0].toInt32();
    var tagStr = String.fromCharCode((tag>>24)&0xFF, (tag>>16)&0xFF, (tag>>8)&0xFF, tag&0xFF);
    console.log('[CALL] FUN_146124a40 tag=0x' + tag.toString(16) + ' ("' + tagStr + '")');
}, function(retval) {
    console.log('[RET]  FUN_146124a40 -> ' + retval);
});

console.log('=== All hooks installed. Press Q in game to trigger connection. ===');
