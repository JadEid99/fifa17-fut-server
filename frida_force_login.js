/*
 * Frida v28: Don't hook the cave directly (crashes).
 * Instead, use a Memory.scan to find what param_1[1] is by reading
 * the RPC object after CreateAccount response arrives.
 * 
 * Hook FUN_146db5d60 (RPC decode) and when we see the CreateAccount
 * response (22 bytes, vtable 0x14389f2b8), read param_1 to find
 * the handler object and its param_1[1].
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== Frida v28: Find state machine object ===');

// Hook FUN_146db5d60 to catch the CreateAccount RPC decode
Interceptor.attach(addr(0x6db5d60), {
    onEnter: function(args) {
        var rpc = args[0];
        var errCode = args[1].toInt32();
        var bodyBuf = args[3];
        
        if (errCode !== 0) return;
        
        var bufStart = bodyBuf.add(0x08).readPointer();
        var bufEnd = bodyBuf.add(0x18).readPointer();
        var bodyLen = bufEnd.sub(bufStart).toInt32();
        
        // CreateAccount response is 22 bytes
        if (bodyLen === 22) {
            console.log('[CA-RPC] Found CreateAccount RPC decode!');
            console.log('[CA-RPC] rpc object=' + rpc);
            
            var vtable = rpc.readPointer();
            console.log('[CA-RPC] rpc vtable=' + vtable);
            
            // Dump the RPC object to find the handler reference
            // The handler is stored somewhere in the RPC object
            // Let's dump offsets 0x00-0x80
            for (var off = 0; off <= 0x80; off += 8) {
                try {
                    var val = rpc.add(off).readPointer();
                    // Check if it looks like a heap pointer (handler object)
                    if (val.compare(ptr('0x1000000')) > 0 && val.compare(ptr('0x800000000')) < 0) {
                        // Check if it has a vtable in the game's code range
                        try {
                            var possibleVtable = val.readPointer();
                            if (possibleVtable.compare(ptr('0x140000000')) > 0 && possibleVtable.compare(ptr('0x150000000')) < 0) {
                                console.log('[CA-RPC] +0x' + off.toString(16) + ' = ' + val + ' -> vtable=' + possibleVtable);
                            }
                        } catch(e) {}
                    }
                } catch(e) {}
            }
        }
    }
});

// Hook the CreateAccount handler response callback
// FUN_146e151d0 is patched to our cave, but the RPC framework calls it
// through a function pointer. Let's hook the function that CALLS the handler
// which is the vtable[0] call in FUN_146db5d60:
// (**(code **)*puVar2)(puVar2, 0);
// This is called after the decode, with the RPC object as param.

// Actually, let's just trace what happens after CreateAccount by hooking
// functions that should be called in the login flow:

// FUN_146e1c3f0 — Login type processor
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        console.log('[LOGIN-PROC] CALLED! This means we got past CreateAccount!');
    }
});

// FUN_146e1e460 — post_PreAuth
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) {
        console.log('[POST-PREAUTH] called');
    }
});

// FUN_146e19720 — Login state machine start
Interceptor.attach(addr(0x6e19720), {
    onEnter: function(args) {
        console.log('[LOGIN-SM-START] FUN_146e19720 called! param1=' + args[0]);
    }
});

// FUN_146e19b30 — Another login state function
Interceptor.attach(addr(0x6e19b30), {
    onEnter: function(args) {
        console.log('[LOGIN-SM-B] FUN_146e19b30 called!');
    }
});

// FUN_146e1dae0 — Login check function
Interceptor.attach(addr(0x6e1dae0), {
    onEnter: function(args) {
        console.log('[LOGIN-CHECK] FUN_146e1dae0 called!');
    }
});

console.log('=== Ready ===');
