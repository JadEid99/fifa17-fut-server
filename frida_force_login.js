/*
 * Frida v15: Trace CreateAccount flow
 * 
 * We're past PreAuth. The game sends CreateAccount (cmd=0x0A) but
 * disconnects after our response. Need to understand why.
 *
 * Hooks:
 * 1. The Blaze RPC response dispatcher to see if our response is received
 * 2. The disconnect/error functions to see what triggers the disconnect
 * 3. The OSDK login flow to see where it fails
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 Frida v15 - CreateAccount Trace === Base=' + base);

// Track all Auth component (0x0001) RPC calls and responses
// Hook FUN_146e00070 area - Authentication component handler
// Actually, let's hook more broadly:

// 1. Hook the disconnect function to see WHY the game disconnects
Interceptor.attach(addr(0x6f1f3b0), {
    onEnter: function(args) {
        var reason = args[1].toInt32();
        console.log('[DISCONNECT] reason=' + reason + ' from:\n' + 
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});

// 2. Hook FUN_146f39a10 (handle disconnect result)
Interceptor.attach(addr(0x6f39a10), {
    onEnter: function(args) {
        var reason = args[1].toInt32();
        console.log('[DISCONNECT_RESULT] reason=' + reason);
    }
});

// 3. Hook the OSDK error logging function FUN_1470dbe40
Interceptor.attach(addr(0x70dbe40), {
    onEnter: function(args) {
        var errCode = args[0].toInt32();
        try {
            var file = args[2].readUtf8String();
            var line = args[3].toInt32();
            var func = args[4].readUtf8String();
            console.log('[OSDK_ERROR] code=0x' + (errCode>>>0).toString(16) + ' ' + func + ' (' + file + ':' + line + ')');
        } catch(e) {
            console.log('[OSDK_ERROR] code=0x' + (errCode>>>0).toString(16));
        }
    }
});

// 4. Hook FUN_1470dbf30 (OSDK debug logging)
Interceptor.attach(addr(0x70dbf30), {
    onEnter: function(args) {
        var level = args[0].toInt32();
        try {
            var msg = args[1].readUtf8String();
            if (msg && msg.length > 0 && msg.length < 200) {
                console.log('[OSDK_LOG] level=' + level + ' ' + msg);
            }
        } catch(e) {}
    }
});

// 5. Monitor connection state changes
var lastState = -1;
setInterval(function() {
    try {
        var pOM = ptr(0x1448a3b20).readPointer();
        if (!pOM.isNull()) {
            var state = pOM.add(0x13b8).readU32();
            if (state !== lastState) {
                console.log('[STATE] connState changed: ' + lastState + ' -> ' + state);
                lastState = state;
            }
        }
    } catch(e) {}
}, 500);

console.log('=== Hooks installed. Press Q to trigger connection. ===');
