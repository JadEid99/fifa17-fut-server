/*
 * Frida v14: Deep RPC trace
 * 
 * Goal: Understand WHY the PreAuth RPC times out (ERR_TIMEOUT = 0x40050000)
 * 
 * Key insight: The RPC framework returns ERR_TIMEOUT, meaning our response
 * either never arrives or can't be matched to the pending request.
 * 
 * This script:
 * 1. Hooks the response handler to see what error codes arrive
 * 2. Hooks the RPC send to see what msgId is assigned
 * 3. Hooks the TLS recv to see raw decrypted data
 * 4. Hooks the Blaze frame parser to see if our response is parsed
 * 5. Does NOT block any functions (let the natural flow happen)
 */
var base = Process.getModuleByName('FIFA17.exe').base;
function addr(off) { return base.add(off); }
console.log('=== FIFA 17 Frida v14 - Deep RPC Trace === Base=' + base);

// 1. Hook FUN_146e1cf10 - the PreAuth response callback
Interceptor.attach(addr(0x6e1cf10), {
    onEnter: function(args) {
        var p1 = args[0];
        var p2 = args[1];
        var p3 = args[2].toInt32();
        console.log('[RESP_CB] param1=' + p1 + ' param2=' + p2 + ' param3=0x' + (p3 >>> 0).toString(16));
        if (p3 === 0) {
            console.log('[RESP_CB] SUCCESS! PreAuth response received!');
            // Read some data from param_2
            try {
                var p2_b8 = p2.add(0xb8).readPointer();
                console.log('[RESP_CB] param2+0xb8=' + p2_b8);
            } catch(e) { console.log('[RESP_CB] param2 read error: ' + e.message); }
        } else {
            console.log('[RESP_CB] ERROR: 0x' + (p3 >>> 0).toString(16) + ' (0x40050000=TIMEOUT)');
        }
    }
});

// 2. Hook FUN_146e19a00 - PreAuth completion handler
Interceptor.attach(addr(0x6e19a00), {
    onEnter: function(args) {
        var p2 = args[1];
        var p3 = args[2];
        console.log('[PREAUTH_DONE] param2=' + p2 + ' param3=' + p3);
    }
});

// 3. Hook FUN_146e1e0f0 - PreAuth RPC sender (builds and sends the request)
Interceptor.attach(addr(0x6e1e0f0), {
    onEnter: function(args) {
        console.log('[PREAUTH_SEND] Sending PreAuth RPC request');
    }
});

// 4. Hook FUN_146e1e460 - post_PreAuth handler
Interceptor.attach(addr(0x6e1e460), {
    onEnter: function(args) {
        console.log('[POST_PREAUTH] Called!');
    }
});

// 5. Hook FUN_146e1d4c0 - the actual RPC dispatch (sends packet on wire)
Interceptor.attach(addr(0x6e1d4c0), {
    onEnter: function(args) {
        var comp = args[0];
        console.log('[RPC_DISPATCH] Dispatching RPC');
    }
});

// 6. Hook FUN_146e18170 - FunctorJob scheduler (called from else branch)
Interceptor.attach(addr(0x6e18170), {
    onEnter: function(args) {
        var callback = args[3];
        var errCode = args[4].toInt32();
        console.log('[FUNCTOR_JOB] callback=' + callback + ' errCode=0x' + (errCode >>> 0).toString(16));
    }
});

// 7. Hook FUN_146dab760 - RPC job creation (assigns msgId)
Interceptor.attach(addr(0x6dab760), {
    onEnter: function(args) {
        this.job = args[0];
        this.comp = args[1].toInt32() & 0xFFFF;
        this.cmd = args[2].toInt32() & 0xFFFF;
    },
    onLeave: function(ret) {
        try {
            // After creation, the job should have a msgId assigned
            // Read the job structure to find the msgId
            console.log('[RPC_JOB] Created: comp=0x' + this.comp.toString(16) + ' cmd=0x' + this.cmd.toString(16));
        } catch(e) {}
    }
});

// 8. Hook ProtoSSL recv to see raw decrypted data coming from server
// FUN_14612d5d0 or similar - let's hook the TLS application data handler
// Actually, let's hook the Blaze frame reader instead

// 9. Hook FUN_146db3e40 - disconnect (DON'T block, just log)
Interceptor.attach(addr(0x6db3e40), {
    onEnter: function(args) {
        console.log('[DISCONNECT] Called from ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
    }
});

// 10. Hook FUN_146db8e40 - connection cleanup (DON'T block, just log)
Interceptor.attach(addr(0x6db8e40), {
    onEnter: function(args) {
        console.log('[CLEANUP] Called');
    }
});

// 11. Hook FUN_146da9570 - callback scheduler
Interceptor.attach(addr(0x6da9570), {
    onEnter: function(args) {
        var callback = args[1];
        console.log('[SCHEDULE] callback=' + callback);
    }
});

// 12. Hook FUN_146dad43c - the dispatched callback
Interceptor.attach(addr(0x6dad43c), {
    onEnter: function(args) {
        var p1 = args[0];
        try {
            var vtable = p1.readPointer();
            var fn = vtable.add(0x10).readPointer();
            console.log('[CALLBACK] vtable=' + vtable + ' fn[0x10]=' + fn);
        } catch(e) {
            console.log('[CALLBACK] Called (vtable read error)');
        }
    }
});

// 13. Hook FUN_146e1c3f0 - PreAuth processor (called from param_3==0 path)
Interceptor.attach(addr(0x6e1c3f0), {
    onEnter: function(args) {
        console.log('[PREAUTH_PROC] Processing PreAuth response data!');
    }
});

// 14. Monitor the connection state
// Read OnlineManager+0x13b8 (connection state) periodically
var stateCheckInterval = setInterval(function() {
    try {
        var pOM = ptr(0x1448a3b20).readPointer();
        if (!pOM.isNull()) {
            var state = pOM.add(0x13b8).readU32();
            var disconnecting = pOM.add(0x13a8).readU8();
            var authFlag = pOM.add(0x4ece).readU8();
            // Only log if something interesting
            if (state !== 0 || disconnecting !== 0) {
                console.log('[STATE] connState=' + state + ' disconnecting=' + disconnecting + ' authFlag=' + authFlag);
            }
        }
    } catch(e) {}
}, 2000);

// 15. Hook FUN_146f2a270 - Login sender
Interceptor.attach(addr(0x6f2a270), {
    onEnter: function(args) {
        console.log('[LOGIN_SENDER] >>> CALLED! Login is being sent!');
    }
});

// 16. Hook FUN_146db6af0 - Login state machine setup
Interceptor.attach(addr(0x6db6af0), {
    onEnter: function(args) {
        console.log('[LOGIN_SM] Login state machine setup called');
    },
    onLeave: function(ret) {
        console.log('[LOGIN_SM] Returned: ' + ret);
    }
});

console.log('=== All hooks installed. Waiting for connection... ===');
