/*
 * Frida v24: Verify CreateAccount DLL bypass works
 * Check if the state transition fires after our cave runs
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v24: CA Bypass Verify ===');

// FUN_146e151d0 — CreateAccount response handler (now patched by DLL cave)
// If the DLL patch works, this hook won't fire (the function is replaced).
// If it DOES fire, the DLL patch didn't apply.
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        console.log('[CA] HANDLER CALLED (DLL patch may not have applied)');
        console.log('[CA] param3=0x' + (args[2].toInt32()>>>0).toString(16));
    }
});

// FUN_146e00f40 — Called on CreateAccount success (notification function)
Interceptor.attach(addr(0x6e00f40), {
    onEnter: function(args) {
        console.log('[CA-SUCCESS] FUN_146e00f40 called! CreateAccount bypass working!');
        console.log('[CA-SUCCESS] arg1=' + args[0] + ' arg2=' + args[1] + ' arg3=' + args[2]);
    }
});

// FUN_146e1e460 — post_PreAuth (sends Ping, triggers login flow)
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) {
        console.log('[POST-PREAUTH] FUN_146e1e460 called');
    }
});

// FUN_146e1c3f0 — Login type processor (should be called after CreateAccount succeeds)
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        console.log('[LOGIN-PROC] FUN_146e1c3f0 called! Login flow starting!');
    }
});

console.log('=== Ready ===');
