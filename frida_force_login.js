/*
 * Frida v16: Trace CreateAccount response handler
 * Hook FUN_146e151d0 to see if param_3 is 0 (success) or error code
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v16 - CreateAccount Response Trace ===');

// Hook FUN_146e151d0 - CreateAccount response handler
Interceptor.attach(addr(0x6e151d0), {
    onEnter: function(args) {
        var p3 = args[2].toInt32();
        console.log('[CREATE_ACCOUNT_RESP] param3=0x' + (p3>>>0).toString(16) + (p3 === 0 ? ' (SUCCESS)' : ' (ERROR)'));
        if (p3 === 0) {
            var p2 = args[1];
            try {
                console.log('[CREATE_ACCOUNT_RESP] param2+0x10=' + p2.add(0x10).readU8());
                console.log('[CREATE_ACCOUNT_RESP] param2+0x11=' + p2.add(0x11).readU8());
                console.log('[CREATE_ACCOUNT_RESP] param2+0x12=' + p2.add(0x12).readU8());
                console.log('[CREATE_ACCOUNT_RESP] param2+0x13=' + p2.add(0x13).readU8());
            } catch(e) { console.log('[CREATE_ACCOUNT_RESP] read error: ' + e); }
        }
    }
});

// Also hook the general RPC response callback to see ALL responses
// FUN_146e1cf10 is our patched PreAuth handler - skip it
// Hook FUN_146e00070 - Authentication component general handler
Interceptor.attach(addr(0x6e00070), {
    onEnter: function(args) {
        var p3 = args[2].toInt32();
        console.log('[AUTH_HANDLER] param3=0x' + (p3>>>0).toString(16));
    }
});

// Hook OSDK error logger to see what errors occur
Interceptor.attach(addr(0x70dbe40), {
    onEnter: function(args) {
        var errCode = args[0].toInt32();
        if (errCode !== 0) {
            try {
                var func = args[4].readUtf8String();
                console.log('[OSDK_ERR] 0x' + (errCode>>>0).toString(16) + ' ' + func);
            } catch(e) {
                console.log('[OSDK_ERR] 0x' + (errCode>>>0).toString(16));
            }
        }
    }
});

// Monitor connection state
var lastState = -1;
setInterval(function() {
    try {
        var pOM = ptr(0x1448a3b20).readPointer();
        if (!pOM.isNull()) {
            var state = pOM.add(0x13b8).readU32();
            if (state !== lastState) {
                console.log('[STATE] ' + lastState + ' -> ' + state);
                lastState = state;
            }
        }
    } catch(e) {}
}, 1000);

console.log('=== Ready ===');
